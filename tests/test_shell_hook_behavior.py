"""Execute emitted hooks in real shells against disposable PATH/status fixtures."""
import os
import json
from pathlib import Path
import shlex
import shutil
import struct
import subprocess
import tempfile
import time
import unittest
import venv

ROOT = Path(__file__).resolve().parents[1]


def emitted_hook(shell, status_file):
    source = (ROOT / "src/hooks/mod.rs").read_text()
    marker = f"const {shell.upper()}_HOOK: &str = r"
    raw = source.split(marker, 1)[1]
    if raw.startswith('#"'):
        hook = raw[2:].split('"#;', 1)[0]
    else:
        hook = raw[1:].split('";', 1)[0]
    return hook.replace("__OMG_STATUS_FILE__", shlex.quote(str(status_file)))


class ShellHookBehavior(unittest.TestCase):
    def shell(self, name):
        path = shutil.which(name)
        if path is None:
            if name in os.environ.get("OMG_HOOK_TEST_REQUIRE_SHELLS", "").split(","):
                self.fail(f"required {name} is unavailable")
            self.skipTest(f"{name} is unavailable; no shell packages are installed by this test")
        return path

    def run_shell(self, shell, script, root, runtime_outputs=None):
        executable = self.shell(shell)
        (root / "hook").write_text(emitted_hook(shell, root / "status"))
        tools = root / "tools"
        tools.mkdir(exist_ok=True)
        omg = tools / "omg"
        omg.write_text('''#!/bin/sh
if [ "$1" = explicit ]; then printf 'cli-fallback\\n' >> "$OMG_TEST_EVENTS"; printf '73\\n'; fi
if [ "$1" = hook-env ]; then
  case "$PWD" in
    "$PROJECT_A") cat "$OUTPUT_A" ;;
    "$PROJECT_B") cat "$OUTPUT_B" ;;
  esac
fi
''')
        omg.chmod(0o755)
        env = {**os.environ, "HOME": str(root), "PATH": str(tools) + ":/usr/bin:/bin",
               "HOOK": str(root / "hook"), "TOOLS": str(tools),
               "OMG_TEST_EVENTS": str(root / "events"), "VENV": str(root / "venv"),
               "USER_ADDED": str(root / "user-tools")}
        env.pop("VIRTUAL_ENV", None)
        if runtime_outputs is not None:
            for name in ("A", "B"):
                (root / f"output-{name}").write_text(runtime_outputs[name])
                env[f"PROJECT_{name}"] = str(root / f"project-{name}")
                env[f"OUTPUT_{name}"] = str(root / f"output-{name}")
                env[f"RUNTIME_{name}"] = str(root / f"data/versions/python/{'3.12.0' if name == 'A' else '3.13.0'}/bin")
            env["PROJECT_NONE"] = str(root / "neutral")
            env["USER_ADDED"] = str(root / "user-tools")
        result = subprocess.run([executable, "-c", script], env=env, text=True,
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stderr, "", result.stderr)
        return result.stdout

    def runtime_outputs(self, shell, root):
        outputs = {}
        for name, version in (("A", "3.12.0"), ("B", "3.13.0")):
            project = root / f"project-{name}"
            project.mkdir()
            (project / ".python-version").write_text(version)
            runtime = root / f"data/versions/python/{version}/bin"
            runtime.mkdir(parents=True)
        (root / "neutral").mkdir()
        binary = os.environ.get("OMG_HOOK_TEST_BINARY")
        captured = os.environ.get("OMG_HOOK_TEST_ENV_OUTPUTS")
        if binary:
            for name in ("A", "B"):
                result = subprocess.run([binary, "hook-env", "-s", shell],
                                        cwd=root / f"project-{name}", text=True, capture_output=True, timeout=15,
                                        env={**os.environ, "OMG_NATIVE_TEST_DATA_DIR": "1",
                                             "OMG_DATA_DIR": str(root / "data")})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, "", result.stderr)
                outputs[name] = result.stdout
        elif captured:
            outputs = json.loads(Path(captured).read_text())[shell]
            for name, version in (("A", "3.12.0"), ("B", "3.13.0")):
                outputs = {key: value.replace(f"__RUNTIME_{name}__", str(root / f"data/versions/python/{version}/bin"))
                           for key, value in outputs.items()}
        else:
            self.skipTest("runtime switching requires actual CLI hook-env output: set OMG_HOOK_TEST_BINARY or captured OMG_HOOK_TEST_ENV_OUTPUTS")
        return outputs

    def switches_only_owned_paths(self, shell):
        self.shell(shell)
        with tempfile.TemporaryDirectory(prefix="omg-hook-switch-") as directory:
            root = Path(directory)
            outputs = self.runtime_outputs(shell, root)
            venv.EnvBuilder(with_pip=False).create(root / "venv")
            if shell == "fish":
                script = '''source "$HOOK"
cd "$PROJECT_NONE"; _omg_hook
source "$VENV/bin/activate.fish"
cd "$PROJECT_A"; _omg_hook
command -s python
deactivate; _omg_hook
string join ':' $PATH
set -gx PATH "$USER_ADDED" $PATH
cd "$PROJECT_B"; _omg_hook
string join ':' $PATH
_omg_hook
string join ':' $PATH
cd "$PROJECT_NONE"; _omg_hook
string join ':' $PATH
'''
            else:
                script = '''. "$HOOK"
cd "$PROJECT_NONE"; _omg_hook
. "$VENV/bin/activate"
cd "$PROJECT_A"; _omg_hook
command -v python
deactivate; _omg_hook
printf '%s\\n' "$PATH"
export PATH="$USER_ADDED:$PATH"
cd "$PROJECT_B"; _omg_hook
printf '%s\\n' "$PATH"
_omg_hook
printf '%s\\n' "$PATH"
cd "$PROJECT_NONE"; _omg_hook
printf '%s\\n' "$PATH"
'''
            lines = self.run_shell(shell, script, root, outputs).splitlines()
            self.assertEqual(lines[0], str(root / "venv/bin/python"))
            paths = [line.split(":") for line in lines[1:]]
            a = str(root / "data/versions/python/3.12.0/bin")
            b = str(root / "data/versions/python/3.13.0/bin")
            self.assertEqual(paths[0][0], a)
            for path in paths[1:3]:
                self.assertEqual(path.count(a), 0)
                self.assertEqual(path.count(b), 1)
                self.assertIn(str(root / "user-tools"), path)
            self.assertEqual(paths[1], paths[2], "repeated prompts must not accumulate runtime paths")
            self.assertEqual(paths[3], [str(root / "user-tools"), str(root / "tools"), "/usr/bin", "/bin"])

            # Activating a venv backs up the selected runtime's PATH. Switching
            # while active must not let deactivate restore that obsolete entry.
            if shell == "fish":
                lifecycle = '''source "$HOOK"
cd "$PROJECT_A"; _omg_hook
source "$VENV/bin/activate.fish"
cd "$PROJECT_B"; _omg_hook
command -s python
deactivate; _omg_hook
string join ':' $PATH
'''
            else:
                lifecycle = '''. "$HOOK"
cd "$PROJECT_A"; _omg_hook
. "$VENV/bin/activate"
cd "$PROJECT_B"; _omg_hook
command -v python
deactivate; _omg_hook
printf '%s\\n' "$PATH"
'''
            lifecycle_lines = self.run_shell(shell, lifecycle, root, outputs).splitlines()
            self.assertEqual(lifecycle_lines[0], str(root / "venv/bin/python"))
            self.assertEqual(lifecycle_lines[1].split(":"),
                             [b, str(root / "tools"), "/usr/bin", "/bin"])

            if shell != "fish":
                control = '''. "$HOOK"
export PATH="$RUNTIME_A:$PATH"
cd "$PROJECT_A"; _omg_hook
cd "$PROJECT_B"; _omg_hook
printf '%s\\n' "$PATH"
'''
                retained = self.run_shell(shell, control, root, outputs).strip().split(":")
                self.assertEqual(retained.count(a), 1, "preexisting user-owned runtime entry must remain")
                self.assertEqual(retained.count(b), 1)
                duplicate_lifecycle = lifecycle.replace('cd "$PROJECT_A";',
                                                        'export PATH="$RUNTIME_A:$PATH"\ncd "$PROJECT_A";', 1)
                restored = self.run_shell(shell, duplicate_lifecycle, root, outputs).splitlines()[1].split(":")
                self.assertEqual(restored.count(a), 1, "deactivation must retain the user-owned duplicate")
                self.assertEqual(restored.count(b), 1)
            else:
                duplicate_lifecycle = lifecycle.replace('cd "$PROJECT_A";',
                                                        'set -gx PATH "$RUNTIME_A" $PATH\ncd "$PROJECT_A";', 1)
                restored = self.run_shell(shell, duplicate_lifecycle, root, outputs).splitlines()[1].split(":")
                self.assertEqual(restored.count(a), 1, "deactivation must retain the user-owned duplicate")
                self.assertEqual(restored.count(b), 1)

    def preserves_venv(self, shell):
        self.shell(shell)
        with tempfile.TemporaryDirectory(prefix="omg-hook-venv-") as directory:
            root = Path(directory)
            venv.EnvBuilder(with_pip=False).create(root / "venv")
            if shell == "fish":
                script = '''source "$HOOK"
_omg_hook
source "$VENV/bin/activate.fish"
set -gx PATH "$USER_ADDED" $PATH
_omg_hook
command -s python
printf '%s\\n' "$VIRTUAL_ENV"
string join ':' $PATH
'''
            else:
                script = '''. "$HOOK"
_omg_hook
. "$VENV/bin/activate"
export PATH="$USER_ADDED:$PATH"
_omg_hook
command -v python
printf '%s\\n' "$VIRTUAL_ENV" "$PATH"
'''
            output = self.run_shell(shell, script, root).splitlines()
            self.assertEqual(output[0], str(root / "venv/bin/python"))
            self.assertEqual(output[1], str(root / "venv"))
            self.assertIn(str(root / "tools"), output[2].split(":"))
            self.assertIn(str(root / "user-tools"), output[2].split(":"))
            self.assertIn(str(root / "venv/bin"), output[2].split(":"))
            self.assertEqual(output[2].split(":").count(str(root / "venv/bin")), 1,
                             "prompts must not accumulate the active venv entry")

    def status_freshness(self, shell):
        self.shell(shell)
        for age, valid, explicit, total in [(0, 0, "45", "123"),
                                           (-1000, 1, "73", "0"),
                                           (31536000, 1, "73", "0"),
                                           ((1 << 63) - int(time.time()), 1, "73", "0")]:
            with self.subTest(shell=shell, age=age), tempfile.TemporaryDirectory(prefix="omg-hook-status-") as directory:
                root = Path(directory)
                (root / "status").write_bytes(struct.pack("<IB3xIIIIQ", 1330464595, 1,
                                                          123, 45, 6, 7, int(time.time()) + age))
                script = '''. "$HOOK"
_omg_status_file_valid; printf '%s\\n' "$?"
omg-explicit-count
omg-total-count
'''
                self.assertEqual(self.run_shell(shell, script, root).splitlines(),
                                 [str(valid), explicit, total])
                events = root / "events"
                self.assertEqual(events.read_text() if events.exists() else "", "cli-fallback\n" if valid else "")

    def test_bash_keeps_real_virtualenv_and_user_path(self):
        self.preserves_venv("bash")

    def test_zsh_keeps_real_virtualenv_and_user_path(self):
        self.preserves_venv("zsh")

    def test_fish_keeps_real_virtualenv_and_user_path(self):
        self.preserves_venv("fish")

    def test_bash_rejects_future_status_and_calls_cli(self):
        self.status_freshness("bash")

    def test_zsh_rejects_future_status_and_calls_cli(self):
        self.status_freshness("zsh")

    def test_zsh_discards_cached_counts_when_status_becomes_invalid(self):
        self.shell("zsh")
        with tempfile.TemporaryDirectory(prefix="omg-hook-cache-") as directory:
            root = Path(directory)
            for name, timestamp in (("status", int(time.time())),
                                    ("future", int(time.time()) + 1000)):
                (root / name).write_bytes(struct.pack("<IB3xIIIIQ", 1330464595, 1,
                                                      123, 45, 6, 7, timestamp))
            script = '''. "$HOOK"
omg-ec; omg-tc; omg-oc; omg-uc
/bin/cp "$HOME/future" "$HOME/status"
_OMG_CACHE_TIME=0; _omg_refresh_cache
_omg_status_file_valid; printf '%s\\n' "$?"
omg-ec; omg-tc; omg-oc; omg-uc
omg-explicit-count
'''
            self.assertEqual(self.run_shell("zsh", script, root).splitlines(),
                             ["45", "123", "6", "7", "1", "0", "0", "0", "0", "73"])
            self.assertEqual((root / "events").read_text(), "cli-fallback\n")

    def test_bash_switches_only_owned_runtime_paths(self):
        self.switches_only_owned_paths("bash")

    def test_zsh_switches_only_owned_runtime_paths(self):
        self.switches_only_owned_paths("zsh")

    def test_fish_switches_only_owned_runtime_paths(self):
        self.switches_only_owned_paths("fish")


if __name__ == "__main__":
    unittest.main(verbosity=2)
