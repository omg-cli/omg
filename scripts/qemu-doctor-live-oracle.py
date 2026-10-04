#!/usr/bin/env python3
"""Validate real live-network Doctor reports without accepting offline-only proof."""
import argparse
import hashlib
import json
from pathlib import Path
import re

TARGETS = {
    'arch': ([('Arch Linux', 'https://archlinux.org'), ('Kernel.org', 'https://kernel.org'),
              ('GitHub', 'https://github.com'), ('AUR', 'https://aur.archlinux.org')],
             ['archlinux.org', 'aur.archlinux.org', 'github.com'], ['archlinux.org', 'kernel.org']),
    'debian': ([('Kernel.org', 'https://kernel.org'), ('GitHub', 'https://github.com')],
               ['kernel.org', 'github.com'], ['github.com', 'kernel.org']),
}
TARGETS['ubuntu'] = TARGETS['debian']
TARGETS['debian-trixie'] = TARGETS['debian']
TARGETS['fedora'] = TARGETS['debian']


def read(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise ValueError('report is missing, linked or oversized')
    return path.read_text(encoding='utf-8')


def issues(text):
    matches = re.findall(r'^Error: doctor found ([1-9][0-9]*) health issue\(s\)$', text, re.MULTILINE)
    if len(matches) != 1:
        raise ValueError('raw Doctor exit lacks one health issue count')
    return int(matches[0])


def basic(text, hosts):
    positives = re.findall(r'^  Internet connectivity \(([^ )]+) reachable\)$', text, re.MULTILINE)
    shadows = re.findall(r'^  PATH resolves a different omg executable first: "([^"\n]+/path-shadow/omg)"$', text, re.MULTILINE)
    if len(positives) != 1 or positives[0] not in hosts or len(shadows) != 1 or 'Connectivity probes failed (' in text:
        raise ValueError('live basic connectivity or known PATH issue is missing')
    return shadows[0]


def verify(args):
    baseline, baseline_err, output, error = [read(path) for path in
                                            (args.baseline_out, args.baseline_err, args.out, args.err)]
    if args.baseline_exit != 1 or args.exit != 1:
        raise ValueError('known PATH shadow must produce raw health exit 1')
    mirrors, hosts, basic_hosts = TARGETS[args.distro]
    if 'Network Diagnostics' in baseline or basic(baseline, basic_hosts) != basic(output, basic_hosts):
        raise ValueError('baseline and network report identity differs')
    if output.count('Network Diagnostics\n') != 1 or output.count('DNS Resolution:\n') != 1:
        raise ValueError('network report sections are missing or duplicated')
    sections = output.split('Network Diagnostics\n', 1)[1].split('DNS Resolution:\n', 1)
    mirror_rows = [re.fullmatch(r'  ([✓✗⚠]) (.+?) \((.+)\)', line)
                   for line in sections[0].splitlines() if line.strip()]
    dns_rows = [re.fullmatch(r'    ([✓✗]) (\S+) \((.+)\)', line)
                for line in sections[1].splitlines() if line.startswith('    ')]
    if any(row is None for row in mirror_rows + dns_rows):
        raise ValueError('malformed network diagnostic')
    if [row[2] for row in mirror_rows] != [name for name, _ in mirrors] or [row[2] for row in dns_rows] != hosts:
        raise ValueError('backend targets are missing, duplicated or incorrect')
    for row, (_, url) in zip(mirror_rows, mirrors):
        if row[1] == '✓':
            valid = re.fullmatch(r'[0-9]+ ms', row[3])
        elif row[1] == '⚠':
            valid = re.fullmatch(r'HTTP [45][0-9]{2}', row[3])
        else:
            valid = row[3] == 'timeout' or re.search(re.escape(url) + r'/?(?=[)\s]|$)', row[3])
        if not valid:
            raise ValueError('mirror outcome lacks its actual status, latency or requested URL')
    for row in dns_rows:
        if row[1] == '✓' and not re.fullmatch(r'[1-9][0-9]* addresses', row[3]):
            raise ValueError('DNS success has no usable addresses')
    http_positive = sum(row[1] == '✓' for row in mirror_rows)
    dns_positive = sum(row[1] == '✓' for row in dns_rows)
    if not http_positive or not dns_positive:
        raise ValueError('live proof requires successful HTTP and DNS observations')
    failed = sum(row[1] != '✓' for row in mirror_rows + dns_rows)
    baseline_count, count = issues(baseline_err), issues(error)
    if count != baseline_count + failed:
        raise ValueError('health issue delta does not match observed failed probes')
    return {'schema_version': 1, 'kind': 'doctor-live-network', 'complete': True,
            'distro': args.distro, 'network_scope': 'network', 'exit_code': args.exit,
            'baseline_exit_code': args.baseline_exit, 'baseline_issues': baseline_count,
            'health_issues': count, 'network_issues': failed,
            'http_positive': http_positive, 'dns_positive': dns_positive,
            'mirror_targets': [name for name, _ in mirrors], 'dns_targets': hosts,
            'oracle_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'report_sha256': hashlib.sha256(output.encode()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--distro', choices=tuple(TARGETS), required=True)
    for name in ('baseline-out', 'baseline-err', 'out', 'err'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--baseline-exit', type=int, required=True)
    parser.add_argument('--exit', type=int, required=True)
    args = parser.parse_args()
    try:
        receipt = verify(args)
    except (OSError, ValueError) as error:
        parser.exit(1, 'live Doctor proof failed: ' + str(error) + '\n')
    print(json.dumps(receipt, sort_keys=True))


if __name__ == '__main__':
    main()
