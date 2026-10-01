#!/usr/bin/env python3
"""Exercise exact legacy export admission and corruption refusal."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ORACLE = Path(__file__).with_name("qemu-audit-log-oracle.py")
SPEC = importlib.util.spec_from_file_location("audit_log_oracle", ORACLE)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class AuditLogOracleTests(unittest.TestCase):
    def check_export(self, change=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run([sys.executable, str(ORACLE), "prepare", directory], check=True)
            original = MODULE.source_bytes()
            self.assertNotIn(b"hash_version", original)
            rows = [dict(MODULE.entries()[index], hash_version=0) for index in (5, 4, 2)]
            if change:
                change(rows)
            export = root / "audit-log-export.json"
            export.write_text(json.dumps(rows))
            export.chmod(0o600)
            result = subprocess.run(
                [sys.executable, str(ORACLE), "check", directory],
                capture_output=True, text=True,
            )
            self.assertEqual((root / "audit-log-data/audit/audit.jsonl").read_bytes(), original)
            return result

    def test_explicit_legacy_version_is_required_and_source_stays_legacy(self):
        self.assertEqual(self.check_export().returncode, 0)

    def test_missing_version_is_rejected(self):
        self.assertNotEqual(self.check_export(lambda rows: rows[0].pop("hash_version")).returncode, 0)

    def test_modern_version_substitution_is_rejected(self):
        self.assertNotEqual(self.check_export(lambda rows: rows[0].update(hash_version=1)).returncode, 0)

    def test_wrong_record_order_is_rejected(self):
        self.assertNotEqual(self.check_export(lambda rows: rows.reverse()).returncode, 0)

    def test_changed_hash_is_rejected(self):
        self.assertNotEqual(self.check_export(lambda rows: rows[0].update(hash="0" * 64)).returncode, 0)

    def test_extra_field_is_rejected(self):
        self.assertNotEqual(self.check_export(lambda rows: rows[0].update(unexpected=True)).returncode, 0)


if __name__ == "__main__":
    unittest.main()
