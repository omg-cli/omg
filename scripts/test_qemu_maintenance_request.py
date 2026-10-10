"""Exercise the maintenance workflow's shell step without writing to GitHub."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]


class MaintenanceRequestTests(unittest.TestCase):
    def run_request(self, existing, failure=False):
        workflow = (ROOT / ".github/workflows/qemu-maintenance.yml").read_text()
        script = textwrap.dedent(workflow.split("        run: |\n", 1)[1])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            cli = path / "gh"
            cli.write_text(textwrap.dedent('''\
                #!/usr/bin/env python3
                import json, os, sys
                from pathlib import Path
                args = sys.argv[1:]
                with Path(os.environ["CALLS"]).open("a") as stream:
                    stream.write(json.dumps(args) + "\\n")
                if args[:2] == ["issue", "list"]:
                    # The unquoted punctuation-heavy search misses the live title.
                    if os.environ["LOOKUP_FAILURE"] == "1":
                        sys.exit(1)
                    sys.exit(0)
                if args[0] == "api":
                    if os.environ["LOOKUP_FAILURE"] == "1":
                        sys.exit(1)
                    assert "--paginate" in args
                    assert "repos/omg-cli/omg/issues?state=open&per_page=100" in args
                    print(os.environ["EXISTING"], end="")
                elif args[:2] == ["issue", "create"]:
                    assert Path(args[args.index("--body-file") + 1]).is_file()
                else:
                    sys.exit(2)
                '''))
            cli.chmod(0o755)
            calls = path / "calls.jsonl"
            environment = dict(os.environ, PATH=f"{path}:{os.environ['PATH']}",
                               GH_REPO="omg-cli/omg", RUNNER_TEMP=directory,
                               CALLS=str(calls), EXISTING=existing,
                               LOOKUP_FAILURE="1" if failure else "0")
            result = subprocess.run(["bash", "-c", script], env=environment,
                                    capture_output=True, text=True, timeout=10)
            commands = [json.loads(line) for line in calls.read_text().splitlines()]
            return result, commands

    def test_existing_request_prevents_duplicate_creation(self):
        result, commands = self.run_request("889\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(command[:2] == ["issue", "create"] for command in commands))

    def test_missing_request_creates_one_labeled_issue(self):
        result, commands = self.run_request("")
        self.assertEqual(result.returncode, 0, result.stderr)
        creations = [command for command in commands if command[:2] == ["issue", "create"]]
        self.assertEqual(len(creations), 1)
        self.assertIn("--label", creations[0])
        self.assertIn("security,type:maintenance,priority:p2", creations[0])

    def test_failed_lookup_never_creates_an_issue(self):
        result, commands = self.run_request("", failure=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(command[:2] == ["issue", "create"] for command in commands))


if __name__ == "__main__":
    unittest.main()
