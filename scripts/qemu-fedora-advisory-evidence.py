#!/usr/bin/env python3
"""Replay native Fedora advisory diagnostics; admission requires native GPG verification.

https://dnf5.readthedocs.io/en/latest/commands/advisory.8.html
https://www.gnupg.org/documentation/manuals/gnupg/GPG-Configuration-Options.html
"""
import argparse
import configparser
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import xml.etree.ElementTree as ET


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


bound = module('fedora_bound_evidence', 'qemu-osv-evidence.py')
oracle = module('fedora_advisory_oracle', 'qemu-fedora-advisory-oracle.py')
ROOT = '/tmp/omg-fedora-advisory-qemu-616'
NS = '{http://linux.duke.edu/metadata/repo}'


def read_bytes(directory, name):
    path = directory/name; metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > bound.MAX_EVIDENCE_BYTES:
        raise ValueError('metadata requires bounded regular files')
    data = path.read_bytes()
    if len(data) > bound.MAX_EVIDENCE_BYTES: raise ValueError('metadata exceeds byte limit')
    return data


def config(text):
    value = configparser.ConfigParser(interpolation=None); value.read_string(text)
    return {section: dict(value.items(section)) for section in value.sections()}


def xml_document(data):
    if b'<!DOCTYPE' in data or b'<!ENTITY' in data: raise ValueError('metadata declarations are refused')
    return ET.fromstring(data)


def validate_structure(directory, archive, fixture):
    try:
        text = lambda name: bound.read_text(directory, name)
        decode = lambda name: json.loads(text(name), object_pairs_hook=bound.unique_object)
        receipt = decode('receipt.json')
        if (receipt.get('schema_version') != 1 or receipt.get('accepted') is not True
                or receipt.get('isolated_vm_mount_and_network') is not True
                or type(receipt.get('ordinary_user_uid')) is not int or receipt['ordinary_user_uid'] <= 0
                or receipt.get('daemon_shutdown') is not True
                or receipt.get('fixture_id') != 'OMG-QEMU-FEDORA-616' or receipt.get('expected_native_severity') != 'Important'
                or receipt.get('scope') != 'native signed metadata-only advisory lifecycle; no package upgrade/download claim'
                or receipt.get('native_archive_sha256') != bound.digest_file(archive)
                or receipt.get('fixture_sha256') != bound.digest_file(fixture)
                or not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', receipt.get('boot_id', ''))
                or not re.fullmatch(r'[A-F0-9]{40}', receipt.get('key_fingerprint', ''))):
            raise ValueError('incomplete or mismatched native Fedora identity')
        hashes = bound.archive_binary_hashes(archive, 'fedora')
        if any(receipt.get(name+'_sha256') != digest for name, digest in hashes.items()):
            raise ValueError('guest binaries differ from admitted native archive')
        if not re.search(r'^ID=(?:fedora|"fedora")$', text('os-release'), re.M): raise ValueError('wrong native distro')
        identity = receipt['native_glibc_identity']; oracle.updateinfo(identity)
        before, after = receipt.get('native_state_before'), receipt.get('native_state_after')
        if not isinstance(before, dict) or set(before) != {'installed', 'explicit', 'reason_sha256'} or before != after or receipt.get('native_state_unchanged') is not True:
            raise ValueError('native installed packages or installation reasons changed')
        for key in ('installed', 'explicit'):
            lines = before[key].splitlines()
            if not lines or lines != sorted(set(lines)) or before[key] != '\n'.join(lines)+'\n': raise ValueError('incomplete native state')
        reasons = before['reason_sha256']
        if not isinstance(reasons, dict) or 'packages.toml' not in reasons or any(
                not isinstance(name, str) or PurePosixPath(name).is_absolute() or '..' in PurePosixPath(name).parts
                or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._/-]*\.toml', name)
                or not isinstance(value, str) or not bound.HASH.fullmatch(value) for name, value in reasons.items()):
            raise ValueError('invalid native installation reason identity')
        rows = [dict(zip(('name','epoch','version','release','arch'), line.split('\t'), strict=True)) for line in text('native-query.tsv').splitlines()]
        if '\n'.join(sorted(text('native-query.tsv').splitlines()))+'\n' != before['installed'] or identity not in rows:
            raise ValueError('native query differs from unchanged installed state')
        foreign = 'aarch64' if identity['arch']=='x86_64' else 'x86_64'
        if any(row['name']=='glibc' and row['arch']==foreign for row in rows): raise ValueError('foreign control architecture is installed')
        newer = 'glibc-'+(identity['epoch']+':' if identity['epoch']!='0' else '')+identity['version']+'-'+identity['release']+'.omgqemu616.'+identity['arch']
        if receipt.get('newer_advisory_nevra') != newer or receipt.get('native_rpm_comparison') != '-1' or text('native-version-comparison.txt').strip() != '-1':
            raise ValueError('native RPM did not prove a newer applicable version')
        original = text('native-dnf-before.conf'); digest = hashlib.sha256(original.encode()).hexdigest()
        if receipt.get('original_dnf_config_sha256') != digest: raise ValueError('native DNF configuration is not bound')
        for phase in ('before','after'):
            if text('parent-system-'+phase+'.sha256') != digest+'  /etc/dnf/dnf.conf\n': raise ValueError('parent DNF configuration changed')
        native_config, private_config = config(original), config(text('private-dnf.conf'))
        expected = {section:dict(values) for section,values in native_config.items()}
        expected.setdefault('main', {})['reposdir'] = ROOT+'/repos'
        if private_config != expected: raise ValueError('private DNF changed more than repository selection')
        repositories = config(text('fixture.repo'))
        required = {'enabled':'1','gpgcheck':'1','repo_gpgcheck':'1','localpkg_gpgcheck':'1','skip_if_unavailable':'false',
                    'baseurl':'file://'+ROOT+'/repo','gpgkey':'file://'+ROOT+'/fixture-key.asc'}
        if set(repositories) != {'omg-qemu-616'} or any(repositories['omg-qemu-616'].get(k)!=v for k,v in required.items()):
            raise ValueError('native repository authentication was weakened')
        commands = decode('commands.json')
        common = ['dnf', '--setopt=cachedir='+ROOT+'/user/cache/dnf-security', '--setopt=system_cachedir='+ROOT+'/user/cache/dnf-security',
                  '--setopt=cacheonly=none', '--setopt=*.skip_if_unavailable=false']
        required_commands = {
            'native-advisory-list': common+['--refresh', 'advisory', 'list', '--available', '--security', '--json'],
            'native-advisory-info': common+['--cacheonly', 'advisory', 'info', '--available', '--security', '--json'],
            'native-repository': common+['--cacheonly', 'repo', 'info', '--enabled', '--json'],
            'dnf-key-admission': common+['--refresh', '-y', 'makecache'],
            'dnf-default-key-admission': ['dnf', '--setopt=*.skip_if_unavailable=false', '--refresh', '-y', 'makecache'],
            'private-config': ['mount', '--bind', ROOT+'/dnf.conf', '/etc/dnf/dnf.conf'],
            'modifyrepo': ['modifyrepo_c', '--compress-type', 'gz', '--mdtype', 'updateinfo', ROOT+'/updateinfo.xml', ROOT+'/repo/repodata'],
        }
        if not isinstance(commands,dict): raise ValueError('missing native command records')
        for label,argv in required_commands.items():
            observed=commands.get(label,{})
            if observed.get('argv')!=argv or type(observed.get('exit_code')) is not int or observed['exit_code']!=0:
                raise ValueError('native setup or advisory command did not succeed: '+label)
        verification=commands.get('verify',{})
        argv=verification.get('argv',[])
        if (type(verification.get('exit_code')) is not int or verification['exit_code']!=0
                or not isinstance(argv,list) or not argv or argv[0]!='gpg'
                or argv[-3:]!=['--verify',ROOT+'/repo/repodata/repomd.xml.asc',ROOT+'/repo/repodata/repomd.xml']):
            raise ValueError('native GPG did not verify the detached metadata signature')
        selected = decode('native-advisory-list.stdout')
        if not isinstance(selected,list) or len(selected)!=1 or any(selected[0].get(k)!=v for k,v in {'name':'OMG-QEMU-FEDORA-616','type':'security','severity':'Important','nevra':newer}.items()):
            raise ValueError('native advisory selection is not the exact positive control')
        detail = decode('native-advisory-info.stdout')
        if (not isinstance(detail,list) or len(detail)!=1 or any(detail[0].get(k)!=v for k,v in {'Name':'OMG-QEMU-FEDORA-616','Type':'security','Severity':'Important'}.items())
                or detail[0].get('collections',{}).get('packages') != [newer]
                or not any(ref.get('Id')=='CVE-OMG-QEMU-616' and ref.get('Type')=='cve' and ref.get('Url')=='https://example.invalid/omg-qemu-616' for ref in detail[0].get('references',[]))):
            raise ValueError('native advisory details disagree with applicability')
        repository = decode('native-repository.stdout')
        required_repo = {'id':'omg-qemu-616','is_enabled':True,'skip_if_unavailable':False,'repo_gpgcheck':True,'pkg_gpgcheck':True,'available_pkgs':0,'pkgs':0,
                         'base_url':['file://'+ROOT+'/repo'],'gpg_key':['file://'+ROOT+'/fixture-key.asc']}
        if not isinstance(repository,list) or len(repository)!=1 or any(type(repository[0].get(k)) is not type(v) or repository[0].get(k)!=v for k,v in required_repo.items()):
            raise ValueError('native repository is not the authenticated metadata-only fixture')
        packed = read_bytes(directory,'updateinfo.xml.gz'); xml = read_bytes(directory,'updateinfo.xml')
        with gzip.GzipFile(fileobj=io.BytesIO(packed)) as compressed: opened = compressed.read(bound.MAX_EVIDENCE_BYTES+1)
        if len(opened)>bound.MAX_EVIDENCE_BYTES or opened!=xml: raise ValueError('compressed native metadata differs from open updateinfo')
        repomd = xml_document(read_bytes(directory,'repomd.xml')); entries = repomd.findall(NS+'data')
        matches = [entry for entry in entries if entry.get('type')=='updateinfo']
        if len(matches)!=1: raise ValueError('signed repository metadata omitted or repeated updateinfo')
        entry = matches[0]
        for label,data in (('checksum',packed),('open-checksum',xml)):
            checksum = entry.find(NS+label)
            if checksum is None or checksum.get('type')!='sha256' or checksum.text!=hashlib.sha256(data).hexdigest(): raise ValueError('signed native metadata checksum mismatch')
        if (entry.find(NS+'size').text != str(len(packed)) or entry.find(NS+'open-size').text != str(len(xml))
                or not re.fullmatch(r'repodata/[0-9a-f]{64}-updateinfo\.xml\.gz',entry.find(NS+'location').get('href',''))):
            raise ValueError('signed native metadata size or path mismatch')
        updates = xml_document(xml).findall('update'); expected_ids = ['OMG-QEMU-FEDORA-616','OMG-QEMU-FEDORA-FIXED','OMG-QEMU-FEDORA-FOREIGN']
        if [row.findtext('id') for row in updates] != expected_ids: raise ValueError('native positive and exclusion controls are incomplete')
        for index,row in enumerate(updates):
            packages = row.findall('./pkglist/collection/package'); wanted = dict(identity)
            if index!=1: wanted['release'] += '.omgqemu616'
            if index==2: wanted['arch']=foreign
            if row.get('type')!='security' or row.findtext('severity')!='Important' or len(packages)!=1 or packages[0].attrib!=wanted:
                raise ValueError('native updateinfo applicability or severity differs')
        results = receipt.get('product_results'); phases = {'untrusted-metadata','direct-plain','direct-findings','daemon-plain','daemon-findings','daemon-before','daemon-after'}
        if not isinstance(results,dict) or set(results)!=phases: raise ValueError('native product lifecycle is incomplete')
        counters=[]
        for phase in sorted(phases):
            metrics=phase in ('daemon-before','daemon-after'); finding=phase.endswith('findings'); expected_exit=int(finding or phase=='untrusted-metadata')
            expected_argv=['metrics'] if metrics else ['audit','scan']+(['--fail-on-findings'] if finding else [])
            result=results[phase]
            if result.get('argv')!=expected_argv or type(result.get('exit_code')) is not int or result['exit_code']!=expected_exit: raise ValueError('native command or exit differs')
            stdout,stderr=text(phase+'.stdout'),text(phase+'.stderr')
            if metrics:
                values=re.findall(r'^omg_security_audit_requests_total (\d+)$',stdout,re.M)
                if len(values)!=1 or stderr.strip(): raise ValueError('native daemon counter is missing')
                counters.append((phase,int(values[0])))
            elif phase=='untrusted-metadata':
                if 'Failed to query native security advisories' not in stderr or 'signature' not in stderr.lower() or 'No vulnerabilities found' in stdout: raise ValueError('tampered metadata did not fail closed')
            else: oracle.verify_native_result(SimpleNamespace(returncode=result['exit_code'],stdout=stdout,stderr=stderr),finding)
        counts=dict(counters)
        if counts['daemon-after']-counts['daemon-before']!=2 or receipt.get('daemon_requests_delta')!=2: raise ValueError('native daemon did not execute two audits')
        return receipt
    except (AssertionError,OSError,UnicodeError,json.JSONDecodeError,KeyError,TypeError,AttributeError,ValueError,ET.ParseError,configparser.Error,bound.tarfile.TarError) as error:
        raise ValueError('native Fedora advisory structure rejected: '+str(error)) from error


def verify_signature(directory, fingerprint):
    public = read_bytes(directory, 'fixture-key.asc')
    signature = read_bytes(directory, 'repomd.xml.asc')
    metadata = read_bytes(directory, 'repomd.xml')
    if not public.startswith(b'-----BEGIN PGP PUBLIC KEY BLOCK-----') or not signature.startswith(b'-----BEGIN PGP SIGNATURE-----'):
        raise ValueError('public key and detached signature envelopes are required')
    with tempfile.TemporaryDirectory(prefix='omg-fedora-signature-') as temporary:
        home = Path(temporary)
        for name, value in (('key.asc', public), ('metadata.asc', signature), ('metadata.xml', metadata)):
            (home/name).write_bytes(value)
        common = ['gpg', '--no-options', '--homedir', str(home), '--batch', '--no-tty',
                  '--no-auto-key-retrieve', '--auto-key-locate', 'clear']
        def execute(arguments):
            result = subprocess.run(common+arguments, stdin=subprocess.DEVNULL,
                                    capture_output=True, text=True, timeout=20)
            if result.returncode or len(result.stdout)>1024*1024 or len(result.stderr)>1024*1024:
                raise ValueError('native GPG rejected signed metadata: '+result.stderr[:2000].strip())
            return result.stdout
        ring = home/'fixture.gpg'
        execute(['--dearmor', '--output', str(ring), str(home/'key.asc')])
        keyring = ['--no-default-keyring', '--keyring', str(ring)]
        identities = execute(keyring+['--with-colons', '--list-keys'])
        observed = [row.split(':')[9] for row in identities.splitlines() if row.startswith('fpr:')]
        if observed != [fingerprint]:
            raise ValueError('signature public key does not match the native fixture fingerprint')
        result = execute(keyring+['--status-fd', '1', '--verify', str(home/'metadata.asc'), str(home/'metadata.xml')])
        verified = re.findall(r'^\[GNUPG:\] VALIDSIG ([A-F0-9]{40}) ', result, re.M)
        rejected = re.search(r'^\[GNUPG:\] (?:BADSIG|ERRSIG|NO_PUBKEY|EXPSIG|EXPKEYSIG|KEYEXPIRED)\b', result, re.M)
        if verified != [fingerprint] or rejected:
            raise ValueError('native GPG did not verify exactly one valid fixture signature')


def validate_evidence(directory, archive, fixture):
    receipt=validate_structure(directory,archive,fixture)
    try: verify_signature(directory,receipt['key_fingerprint'])
    except (OSError,UnicodeError,subprocess.TimeoutExpired,ValueError) as error: raise ValueError('native Fedora signature rejected: '+str(error)) from error
    return receipt


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--evidence-dir',type=Path,required=True);parser.add_argument('--archive',type=Path,required=True)
    args=parser.parse_args()
    try: validate_evidence(args.evidence_dir,args.archive,Path(__file__).with_name('qemu-fedora-advisory-oracle.py'))
    except ValueError as error: parser.exit(1,str(error)+'\n')
    print('Complete archive-bound signed native Fedora advisory evidence accepted')


if __name__=='__main__':
    main()