import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
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

    def test_prepare_cargo_source_rejects_moving_refs_before_creating_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "prepared"
            with self.assertRaisesRegex(ValueError, "full immutable commit"):
                pins.prepare_cargo_source(destination, "HEAD", {}, source=root.as_uri())
            self.assertFalse(destination.exists())

    def test_prepare_cargo_source_uses_the_exact_commit_without_the_website_theme(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            upstream = root / "upstream"
            upstream.mkdir()

            def git(*args):
                return subprocess.check_output(
                    ["git", "-C", str(upstream), "-c", "core.autocrlf=false", "-c", "user.name=Test", "-c",
                     "user.email=test@example.com", "-c", "commit.gpgsign=false", *args],
                    text=True,
                ).strip()

            git("init", "--quiet")
            workspace_manifest = '[workspace]\nmembers = ["alpm-types", "unused"]\n'
            (upstream / "Cargo.toml").write_text(workspace_manifest, encoding="utf-8")
            (upstream / "alpm-types").mkdir()
            manifest = b'[package]\nname = "alpm-types"\nversion = "0.14.0"\n'
            (upstream / "alpm-types/Cargo.toml").write_bytes(manifest)
            (upstream / "unused").mkdir()
            (upstream / "unused/Cargo.toml").write_text(
                '[package]\nname = "unused"\nversion = "0.1.0"\n', encoding="utf-8",
            )
            (upstream / ".gitmodules").write_text(
                '[submodule "theme"]\npath = alpm-lint-website/themes/linkita\n'
                'url = ../unavailable\n', encoding="utf-8",
            )
            git("add", ".")
            git("update-index", "--add", "--cacheinfo",
                f"160000,{'1' * 40},alpm-lint-website/themes/linkita")
            git("commit", "--quiet", "-m", "Pinned workspace")
            revision = git("rev-parse", "HEAD")
            (upstream / "alpm-types/Cargo.toml").write_bytes(b"uncommitted")

            destination = root / "prepared"
            pins.prepare_cargo_source(destination, revision, {"alpm-types": "0.14.0"},
                                      source=upstream.as_uri())
            config = tomllib.loads((destination / "cargo-config.toml").read_text())["source"]
            pin = config["alpm-pin"]
            self.assertEqual((pin["git"], pin["rev"]), (pins.UPSTREAM, revision))
            snapshot = Path(config[pin["replace-with"]]["directory"])
            self.assertEqual((snapshot / "Cargo.toml").read_text(), workspace_manifest)
            self.assertEqual((snapshot / "alpm-types/Cargo.toml").read_bytes(), manifest)
            checksums = json.loads((snapshot / "alpm-types/.cargo-checksum.json").read_text())
            self.assertEqual(checksums, {
                "package": None, "files": {"Cargo.toml": hashlib.sha256(manifest).hexdigest()},
            })
            self.assertTrue((snapshot / "unused/.cargo-checksum.json").is_file())
            self.assertEqual(list((snapshot / "alpm-lint-website/themes/linkita").glob("*")), [])


if __name__ == "__main__":
    unittest.main()
