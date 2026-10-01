#!/usr/bin/env python3
"""Validate a successful enterprise audit export inside a disposable guest."""

import csv
import json
import os
from pathlib import Path
import stat
import sys


EXPECTED = {'limitations.json', 'change-log.json', 'policy-enforcement.json',
            'installed-packages.csv', 'sbom-inventory.json'}


def valid(root):
    files = list(root.iterdir())
    if {path.name for path in files} != EXPECTED or len(files) != len(EXPECTED):
        return False
    for path in files:
        metadata = path.lstat()
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077):
            return False
    limitations = json.loads((root / 'limitations.json').read_text())
    if not any(item.get('artifact') == 'access-control-matrix'
               and item.get('reason') for item in limitations.get('unavailable_evidence', [])):
        return False
    if not isinstance(json.loads((root / 'change-log.json').read_text()), list):
        return False
    if not isinstance(json.loads((root / 'policy-enforcement.json').read_text()), dict):
        return False
    sbom = json.loads((root / 'sbom-inventory.json').read_text())
    if (sbom.get('bomFormat') != 'CycloneDX' or sbom.get('specVersion') != '1.5'
            or not isinstance(sbom.get('components'), list) or not sbom['components']):
        return False
    with (root / 'installed-packages.csv').open(newline='') as stream:
        reader = csv.DictReader(stream)
        return reader.fieldnames == ['package', 'version', 'description'] and bool(list(reader))


if __name__ == '__main__':
    try:
        raise SystemExit(0 if len(sys.argv) == 2 and valid(Path(sys.argv[1])) else 1)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        raise SystemExit(1)
