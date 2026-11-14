import copy
import importlib.util
from pathlib import Path
import tomllib
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("alpm_pins", HERE / "check-alpm-pins.py")
pins = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pins)


class AlpmPinsTests(unittest.TestCase):
    def setUp(self):
        self.manifest = tomllib.loads((HERE.parent / "Cargo.toml").read_text())
        self.lock = tomllib.loads((HERE.parent / "Cargo.lock").read_text())

    def test_committed_family_is_coherent(self):
        revision, versions = pins.validate(self.manifest, self.lock)
        self.assertEqual(len(revision), 40)
        self.assertEqual(set(versions), pins.FAMILY)

    def test_mixed_manifest_revision_is_refused(self):
        self.manifest["dependencies"]["alpm-db"]["rev"] = "0" * 40
        with self.assertRaises(ValueError):
            pins.validate(self.manifest, self.lock)

    def test_mtree_direct_dependency_cannot_escape_the_family_snapshot(self):
        self.manifest["dependencies"]["alpm-mtree"]["rev"] = "0" * 40
        with self.assertRaises(ValueError):
            pins.validate(self.manifest, self.lock)

    def test_old_transitive_snapshot_is_refused(self):
        package = next(p for p in self.lock["package"] if p["name"] == "alpm-parsers")
        package["source"] = package["source"].replace(package["source"].split("#")[1], "0" * 40)
        with self.assertRaises(ValueError):
            pins.validate(self.manifest, self.lock)

    def test_duplicate_or_wrong_locked_version_is_refused(self):
        package = next(p for p in self.lock["package"] if p["name"] == "alpm-types")
        self.lock["package"].append(copy.deepcopy(package))
        with self.assertRaises(ValueError):
            pins.validate(self.manifest, self.lock)
        self.lock["package"].pop()
        package["version"] = "0.0.0"
        with self.assertRaises(ValueError):
            pins.validate(self.manifest, self.lock)


if __name__ == "__main__":
    unittest.main()
