"""Behavioral regressions for installer, benchmark and verification boundaries."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def function(path, name):
    text = (ROOT / path).read_text()
    match = re.search(rf"^{re.escape(name)}\(\) \{{\n.*?^\}}", text, re.M | re.S)
    if match is None:
        raise AssertionError(f"Missing production function {name}")
    return match.group()


@unittest.skipUnless(os.name == "posix", "requires Bash and POSIX filesystem")
class AuditShellRepairs(unittest.TestCase):
    def run_bash(self, script, **env):
        return subprocess.run(["bash", "-c", script], env={**os.environ, **env},
                              text=True, capture_output=True, timeout=20)

    def benchmark(self, stubs):
        return self.run_bash(function("benches/aur_install_bench.sh", "uninstall_package") +
                             "\n" + function("benches/aur_install_bench.sh", "benchmark_install") +
                             "\n" + stubs + '\nbenchmark_install yay fixture')

    def test_bash_prompt_preserves_existing_interrupt_trap(self):
        hook = (ROOT / "src/hooks/mod.rs").read_text().split('const BASH_HOOK: &str = r#"', 1)[1].split('"#;', 1)[0]
        code = re.search(r"^_omg_hook\(\) \{\n.*?^\}", hook, re.M | re.S).group()
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "omg"
            binary.write_text("#!/bin/sh\nexit 0\n")
            binary.chmod(0o755)
            result = self.run_bash(code + '''
trap 'printf original-handler' INT
before=$(trap -p INT)
_omg_hook
after=$(trap -p INT)
[[ "$before" == "$after" ]]
''', PATH=directory + ":" + os.environ["PATH"])
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def zsh_trap_check(self, trap_setup, snapshot):
        hook = (ROOT / "src/hooks/mod.rs").read_text().split('const ZSH_HOOK: &str = r#"', 1)[1].split('"#;', 1)[0]
        code = re.search(r"^_omg_hook\(\) \{\n.*?^\}", hook, re.M | re.S).group()
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "omg"
            binary.write_text("#!/bin/sh\nexit 0\n")
            binary.chmod(0o755)
            script = code + '\n_omg_refresh_cache() { :; }\n' + trap_setup + '\n' + snapshot + ' > "$TRAP_FILE.before"\n_omg_hook\n' + snapshot + ' > "$TRAP_FILE.after"\n[[ -s "$TRAP_FILE.before" ]] && cmp -s "$TRAP_FILE.before" "$TRAP_FILE.after"'
            result = subprocess.run(["zsh", "-f", "-c", script], text=True, capture_output=True,
                                    env={**os.environ, "PATH": directory + ":" + os.environ["PATH"], "TRAP_FILE": str(Path(directory) / "trap")}, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(shutil.which("zsh"), "requires Zsh")
    def test_zsh_prompt_preserves_existing_interrupt_trap(self):
        self.zsh_trap_check("trap 'printf original-handler' INT", "trap")

    @unittest.skipUnless(shutil.which("zsh"), "requires Zsh")
    def test_zsh_prompt_preserves_function_interrupt_trap(self):
        self.zsh_trap_check("TRAPINT() { printf original-handler; return 130; }", "functions TRAPINT")

    def test_benchmark_stdout_is_only_the_duration(self):
        result = self.benchmark('''
pacman() { return 1; }
yay() { printf 'installer progress\\n'; }
bc() { printf '1.25\\n'; }
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "1.25\n")

    def test_benchmark_refuses_failed_removal(self):
        result = self.benchmark('''
pacman() { return 0; }
sudo() { return 42; }
yay() { printf 'INSTALL EXECUTED\\n'; }
bc() { printf '1.25\\n'; }
''')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("INSTALL EXECUTED", result.stdout + result.stderr)

    def test_benchmark_refuses_package_remaining_after_removal(self):
        result = self.benchmark('''
pacman() { return 0; }
sudo() { return 0; }
yay() { printf 'INSTALL EXECUTED\\n'; }
bc() { printf '1.25\\n'; }
''')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("INSTALL EXECUTED", result.stdout + result.stderr)

    def test_uninstall_preserves_rc_when_backup_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            rc = home / ".bashrc"
            original = '# keep me\neval "$(omg hook bash)"\n'
            rc.write_text(original)
            (home / ".bashrc.omg-backup").symlink_to(home / "absent" / "backup")
            script = 'source <(sed \'$d\' "$INSTALLER")\nuninstall_omg'
            result = self.run_bash(script, HOME=directory, INSTALL_DIR=str(home / "bin"),
                                   INSTALLER=str(ROOT / "install.sh"))
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(rc.read_text(), original)
            self.assertNotIn("Removed OMG integration", result.stdout)

    def test_verify_rejects_newer_vendored_build_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            vendor = root / "vendor" / "rust-apt-0.11.3"
            vendor.mkdir(parents=True)
            for name in ("Cargo.toml", "Cargo.lock", "src/lib.rs"):
                (root / name).write_text("fixture")
                os.utime(root / name, (100, 100))
            binary = root / "omg"
            binary.write_text("#!/bin/sh\nexit 0\n")
            binary.chmod(0o755)
            os.utime(binary, (200, 200))
            (vendor / "build.rs").write_text("changed build input")
            os.utime(vendor / "build.rs", (300, 300))
            result = self.run_bash(function(".pi/skills/verify-omg/bin/verify-omg",
                                            "require_fresh_binary") + '\nrequire_fresh_binary',
                                   REPO_ROOT=str(root), OMG_BIN=str(binary))
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_verify_rejects_changed_bytes_even_with_preserved_mtime(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "vendor").mkdir()
            for name in ("Cargo.toml", "Cargo.lock", "src/lib.rs"):
                (root / name).write_text("fixture")
                os.utime(root / name, (100, 100))
            binary = root / "omg"
            binary.write_text("#!/bin/sh\nexit 0\n")
            binary.chmod(0o755)
            os.utime(binary, (200, 200))
            helper = ".pi/skills/verify-omg/bin/verify-omg"
            functions = "\n".join(function(helper, name) for name in
                                  ("build_input_paths", "source_digest", "build_receipt", "require_fresh_binary"))
            receipt = self.run_bash(functions + '\nbuild_receipt > "$OMG_BIN.source-sha256"\nrequire_fresh_binary',
                                    REPO_ROOT=str(root), OMG_BIN=str(binary))
            self.assertEqual(receipt.returncode, 0, receipt.stdout + receipt.stderr)
            (root / "src/lib.rs").write_text("different bytes, same file timestamp")
            os.utime(root / "src/lib.rs", (100, 100))
            result = self.run_bash(functions + '\nrequire_fresh_binary',
                                   REPO_ROOT=str(root), OMG_BIN=str(binary))
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_verify_rejects_replaced_binary_with_unchanged_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "vendor").mkdir()
            for name in ("Cargo.toml", "Cargo.lock", "src/lib.rs"):
                (root / name).write_text("fixture")
                os.utime(root / name, (100, 100))
            binary = root / "omg"
            binary.write_text("#!/bin/sh\nprintf original\n")
            binary.chmod(0o755)
            os.utime(binary, (200, 200))
            helper = ".pi/skills/verify-omg/bin/verify-omg"
            functions = "\n".join(function(helper, name) for name in
                                  ("build_input_paths", "source_digest", "build_receipt", "require_fresh_binary"))
            receipt = self.run_bash(functions + '\nbuild_receipt > "$OMG_BIN.source-sha256"\nrequire_fresh_binary',
                                    REPO_ROOT=str(root), OMG_BIN=str(binary))
            self.assertEqual(receipt.returncode, 0, receipt.stdout + receipt.stderr)
            binary.write_text("#!/bin/sh\nprintf different-build\n")
            os.utime(binary, (200, 200))
            result = self.run_bash(functions + '\nrequire_fresh_binary',
                                   REPO_ROOT=str(root), OMG_BIN=str(binary))
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
