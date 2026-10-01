"""Security invariants for daemon executable resolution."""

from pathlib import Path
import unittest


SOURCE = (
    Path(__file__).parents[1] / "src" / "cli" / "commands.rs"
).read_text(encoding="utf-8")


class DaemonPathSecurityTests(unittest.TestCase):
    def test_daemon_never_falls_back_to_ambient_path(self):
        resolver = SOURCE.split("fn resolve_omgd_path()", 1)[1].split(
            "fn run_daemon_foreground", 1
        )[0]
        self.assertNotIn('PathBuf::from("omgd")', resolver)
        self.assertIn('root_controlled_program_path("omgd")', resolver)


if __name__ == "__main__":
    unittest.main()
