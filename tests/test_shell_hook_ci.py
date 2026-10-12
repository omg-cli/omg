"""Execute the workflow's shell-test step with each required shell unavailable."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ShellHookCiContract(unittest.TestCase):
    def test_workflow_executes_hooks_and_requires_available_shells(self):
        binary = os.environ.get("OMG_HOOK_TEST_BINARY")
        if not binary:
            self.skipTest("set OMG_HOOK_TEST_BINARY to the built debug CLI")
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        # Read this deliberately small YAML step. Unsupported forms fail loudly;
        # the assertions below observe the executed step, not its spelling.
        marker = "      - name: Test emitted shell hooks\n"
        self.assertIn(marker, workflow, "the workflow has no executable hook-test step")
        step = workflow.split(marker, 1)[1].split("\n      - name:", 1)[0]
        environment, block = step.split("        run: |\n", 1)
        settings = {}
        in_environment = False
        for line in environment.splitlines():
            if line == "        env:":
                in_environment = True
            elif in_environment and line.startswith("          "):
                name, value = line.strip().split(":", 1)
                settings[name] = value.strip()
        script = textwrap.dedent(block)
        # Exclude only this fixture's own invocation to prevent recursion. The
        # actual behavior-suite command and binary guard execute unchanged.
        script = "\n".join(line for line in script.splitlines() if "test_shell_hook_ci.py" not in line)
        runner = shutil.which("bash")
        self.assertIsNotNone(runner, "the executable CI contract needs a Bash runner")
        for missing in ("bash", "zsh", "fish"):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory(prefix="omg-hook-ci-") as directory:
                commands = Path(directory)
                for name in ("bash", "python3", "zsh", "fish"):
                    executable = shutil.which(name)
                    if executable and name != missing:
                        (commands / name).symlink_to(executable)
                # Run the actual step while the requested shell is unavailable
                # to the behavior suite, even if installed on the CI host.
                env = dict(os.environ)
                env.pop("OMG_HOOK_TEST_REQUIRE_SHELLS", None)
                env.update(settings)
                env.update(PATH=str(commands), OMG_HOOK_TEST_BINARY=binary)
                result = subprocess.run([runner, "-c", script], cwd=ROOT,
                                        env=env, text=True, capture_output=True, timeout=60)
                output = result.stdout + result.stderr
                self.assertNotEqual(result.returncode, 0, output)
                self.assertIn(f"required {missing} is unavailable", output)
                self.assertNotIn(f"skipped '{missing} is unavailable", output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
