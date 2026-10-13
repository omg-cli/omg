"""Source-only contract candidate. Root supplies a reviewed genuine execution context."""
from pathlib import Path
import unittest
import provenance


class RegistrySnapshotContract(unittest.TestCase):
    context = None

    def test_locked_registry_source_without_vendor_checksum_is_accepted(self):
        context = type(self).context
        if context is None:
            raise RuntimeError("ADMISSION_HOLD: reviewed genuine provider/runtime context required")
        out, provider, baseline, execute, env, hash_file, write = context
        self.assertEqual(
            hash_file(baseline / "Cargo.lock"),
            "e0707b92546ce332a3732c0ae1465745fcc91f40a5b236ac7b3a36b9f87d6581",
        )
        registry = Path(env["CARGO_HOME"]) / "registry"
        archives = list((registry / "cache").glob("*/itoa-1.0.17.crate"))
        sources = list((registry / "src").glob("*/itoa-1.0.17"))
        if len(archives) != 1 or len(sources) != 1:
            raise RuntimeError("ADMISSION_HOLD: genuine pre-fetched isolated itoa registry pair required")
        archive, source = archives[0], sources[0]
        self.assertEqual(archive.parent.name, source.parent.name)
        self.assertEqual(
            hash_file(archive, 256 * 1024**2),
            "92ecc6618181def0457392ccd0ee51198e065e016d1d527a7ac1b6dc7c1f09d2",
        )
        if (source / ".cargo-checksum.json").exists():
            raise RuntimeError("ADMISSION_HOLD: fixture must reflect real registry cache, without vendor checksum")
        self.assertEqual((source / ".cargo-ok").read_bytes(), b'{"v":1}')
        try:
            result, roots = provenance.snapshot(
                out, provider, baseline, execute, env, hash_file, write
            )
        except FileNotFoundError as error:
            if error.filename != str(source / ".cargo-checksum.json"):
                raise
            self.fail(
                "REGISTRY_LAYOUT_CONTRACT: a locked genuine Cargo registry tree must be verified "
                "without requiring directory-source .cargo-checksum.json"
            )
        self.assertEqual(
            result["status"],
            "REAL_PROVIDER_CAPTURE_REQUIRES_INDEPENDENT_POSTRUN_ADMISSION",
        )
        self.assertEqual(
            [(row["name"], row["version"], row["archive_sha256"])
             for row in result["locked_registry_checksums"]],
            [("itoa", "1.0.17", "92ecc6618181def0457392ccd0ee51198e065e016d1d527a7ac1b6dc7c1f09d2")],
        )
        self.assertIn(str(registry / "src"), result["roots"])
        self.assertIn(str(registry / "cache"), result["roots"])
        provenance.verify(result, roots, hash_file)
