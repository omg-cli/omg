# pyright: strict
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

CI_YML = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "ci.yml"


class ReleaseLockstepTests(unittest.TestCase):
    def test_fuzz_lock_tracks_root_crate_version(self) -> None:
        root = CI_YML.parents[2]
        manifest = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
        fuzz_lock = tomllib.loads((root / "fuzz" / "Cargo.lock").read_text(encoding="utf-8"))
        local_omg = [
            package["version"]
            for package in fuzz_lock["package"]
            if package["name"] == "omg" and "source" not in package
        ]
        self.assertEqual(local_omg, [manifest["package"]["version"]])


def job_block(text: str, job: str) -> str:
    """Return the YAML block for `job:` up to the next top-level job key."""
    start = text.index(f"\n  {job}:")
    rest = text[start + 1 :]
    nxt = re.search(r"\n  [a-zA-Z0-9_-]+:\n", rest[1:])
    end = start + 1 + nxt.start() + 1 if nxt else len(text)
    return text[start:end]


class QuickGateOfflineTests(unittest.TestCase):
    def test_quick_gate_does_no_network_install_and_keeps_gate_fast(self) -> None:
        text = CI_YML.read_text(encoding="utf-8")
        gate = job_block(text, "quick-gate")
        self.assertNotIn(
            "apt-get",
            gate,
            "quick-gate must not apt-install (network); "
            "shell-completion check belongs in the portable job",
        )
        self.assertNotIn(
            "shell_completion.zsh",
            gate,
            "quick-gate must not run the interactive zsh completion test",
        )
        m = re.search(r"timeout-minutes:\s*(\d+)", gate)
        if m is None:
            self.fail("quick-gate must declare timeout-minutes")
        self.assertLessEqual(
            int(m.group(1)),
            10,
            f"quick-gate timeout must stay <= 10 min, got {m.group(1)}",
        )
        self.assertNotIn("Swatinem/rust-cache", gate)
        self.assertNotIn("cargo check", gate)
        self.assertNotIn("cargo clippy", gate)
        self.assertIn("components: rustfmt", gate)
        portable = job_block(text, "portable")
        self.assertIn(
            "shell_completion.zsh",
            portable,
            "portable job must own the relocated shell-completion check",
        )
        self.assertIn(
            "--error-on=any",
            portable,
            "portable apt update must fail closed with --error-on=any + retry",
        )
        self.assertIn(
            "timeout -k 10s 30s zsh tests/shell_completion.zsh",
            portable,
            "relocated completion check must keep its timeout bound",
        )


class FedoraSetupSourceTests(unittest.TestCase):
    def test_fedora_setup_preserves_metalinks_and_fails_missing_repositories(self) -> None:
        commands: list[tuple[str, str]] = []
        for workflow in [CI_YML, CI_YML.with_name("release.yml")]:
            source = workflow.read_text(encoding="utf-8")
            matches = re.findall(r"timeout -k 10s 12m dnf(?:[^\n]*\\\n)*[^\n]*", source)
            self.assertEqual(len(matches), 1)
            commands.append((workflow.name, matches[0]))
        matrix = CI_YML.with_name("qemu-matrix.yml").read_text(encoding="utf-8")
        for encoded in re.findall(r'"setup":\s*("(?:\\.|[^"\\])*")', matrix):
            setup = json.loads(encoded)
            if "12m dnf" in setup:
                command = re.search(r"timeout -k 10s 12m dnf(?:[^\n]*\\\n)*[^\n]*", setup)
                self.assertIsNotNone(command)
                if command is not None:
                    commands.append(("qemu-matrix.yml", command.group()))
        self.assertEqual(len(commands), 4)
        for workflow, command in commands:
            with self.subTest(workflow=workflow, command=command):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    executable = root / "dnf"
                    executable.write_text(
                        f"#!{sys.executable}\n"
                        "import json,os,sys\n"
                        "from pathlib import Path\n"
                        "args=sys.argv[1:]\n"
                        "Path(os.environ['DNF_CALL']).write_text(json.dumps(args))\n"
                        "overrides=[arg for arg in args if arg.startswith('--setopt=') and any(name in arg for name in ('.metalink=', '.baseurl='))]\n"
                        "if overrides or '--setopt=*.skip_if_unavailable=False' not in args:\n"
                        " print('setup refused: image metalinks and fatal repository failures required',file=sys.stderr)\n"
                        " sys.exit(42)\n"
                        "if '--nogpgcheck' in args:\n"
                        " sys.exit(43)\n",
                        encoding="utf-8",
                    )
                    executable.chmod(0o755)
                    receipt = root / "call.json"
                    result = subprocess.run(
                        ["bash", "-e", "-c", command],
                        cwd=root,
                        env=dict(os.environ, PATH=f"{root}:{os.environ['PATH']}", DNF_CALL=str(receipt)),
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    arguments = json.loads(receipt.read_text(encoding="utf-8"))
                    package_index = arguments.index("--setopt=install_weak_deps=False") + 1
                    expected = ["git", "clang", "cmake", "openssl-devel", "pkgconfig", "findutils", "curl"]
                    if workflow != "release.yml":
                        expected.append("procps-ng")
                    if workflow == "ci.yml":
                        expected.append("python3")
                    expected.extend(["rpm", "dnf", "sqlite", "yum-utils", "fedora-release"])
                    self.assertEqual(arguments[package_index:], expected)
                    self.assertEqual(arguments.count("install"), 1)
                    self.assertEqual(arguments.count("-y"), 1)

    def test_fedora_build_setup_keeps_mirror_policy_and_bounded_install_once(self) -> None:
        workflows = [
            CI_YML,
            CI_YML.with_name("qemu-matrix.yml"),
            CI_YML.with_name("release.yml"),
        ]
        for workflow in workflows:
            with self.subTest(workflow=workflow.name):
                source = workflow.read_text(encoding="utf-8")
                expected = 2 if workflow.name == "qemu-matrix.yml" else 1
                self.assertEqual(source.count("--setopt='*.skip_if_unavailable=False'"), expected)
                self.assertNotIn("--setopt=fedora.metalink=", source)
                self.assertNotIn("--setopt=updates.metalink=", source)
                self.assertNotIn("--setopt=fedora.baseurl=", source)
                self.assertNotIn("--setopt=updates.baseurl=", source)
                self.assertEqual(source.count("timeout -k 10s 12m dnf"), expected)
                self.assertNotIn("dnf makecache --refresh", source)
                self.assertNotIn("--nogpgcheck", source)


class QemuConcurrencyTests(unittest.TestCase):
    def test_matrix_jobs_have_distinct_concurrency_groups(self) -> None:
        workflow = CI_YML.with_name("qemu-matrix.yml").read_text(encoding="utf-8")
        groups: list[str] = []
        # x64 lanes inherit parent-workflow cancellation. A reusable workflow
        # must not reuse the parent's group and cancel its own caller.
        lane = CI_YML.with_name("qemu-lane.yml").read_text(encoding="utf-8")
        self.assertNotIn("concurrency:", lane)
        self.assertIn("uses: ./.github/workflows/qemu-lane.yml", job_block(workflow, "guest"))
        for job in ["build-staged-arm", "guest-arm"]:
            block = job_block(workflow, job)
            match = re.search(r"^      group: (.+)$", block, re.MULTILINE)
            if match is None:
                self.fail(f"{job} must declare its concurrency group")
            group = match.group(1)
            self.assertNotIn(
                "github.job", group, "github.job is empty during group evaluation"
            )
            self.assertIn("github.workflow", group)
            self.assertIn("github.event_name", group)
            self.assertIn("matrix.distro", group)
            groups.append(group)
        self.assertEqual(
            len(set(groups)),
            len(groups),
            "architecture/job legs must not cancel each other",
        )


class LocalCiGateExecutesTests(unittest.TestCase):
    def test_local_ci_gate_executes_recipes_instead_of_dry_run(self) -> None:
        text = CI_YML.read_text(encoding="utf-8")
        gate = job_block(text, "quick-gate")
        self.assertNotIn(
            "make -n",
            gate,
            "quick-gate must not use `make -n` dry-run: it never executes recipes",
        )
        self.assertRegex(
            gate,
            r"run:\s*make ci-workflow-quick",
            "quick-gate must really execute `make ci-workflow-quick`",
        )


class CiDeduplicationTests(unittest.TestCase):
    def test_quick_gate_executes_shared_checks_only_once(self) -> None:
        gate = job_block(CI_YML.read_text(encoding="utf-8"), "quick-gate")
        self.assertEqual(gate.count("run: make ci-workflow-quick"), 1)
        result = subprocess.run(
            ["make", "--no-print-directory", "--dry-run", "ci-workflow-quick"],
            cwd=CI_YML.parents[2],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        for command in [
            "cargo fmt --all -- --check",
            "python3 -m unittest discover -s scripts -p 'test_*.py'",
            "python3 tests/test_benchmark_records.py",
        ]:
            with self.subTest(command=command):
                self.assertNotIn(command, gate)
                self.assertEqual(result.stdout.count(command), 1)
        self.assertNotIn("run: make check-shell-syntax", gate)
        self.assertEqual(result.stdout.count("bash -n"), 1)
        self.assertNotIn("cargo check", result.stdout)
        self.assertNotIn("cargo clippy", result.stdout)

    def test_portable_keeps_tests_and_lints_without_repeating_gate_compilation(
        self,
    ) -> None:
        portable = job_block(CI_YML.read_text(encoding="utf-8"), "portable")
        self.assertIn("needs: quick-gate", portable)
        fuzz = "cargo check --manifest-path fuzz/Cargo.toml --all-targets --locked"
        self.assertEqual(portable.count("cargo check"), 1)
        self.assertIn(fuzz, portable)
        self.assertIn("CARGO_TARGET_DIR: ${{ github.workspace }}/target", portable)
        self.assertIn("cargo clippy --all-targets", portable)
        self.assertIn("--features debian-pure", portable)
        self.assertIn("python3 scripts/run-native-contracts.py --features pgp,license", portable)
        makefile = (CI_YML.parents[2] / "Makefile").read_text(encoding="utf-8")
        self.assertIn(
            fuzz,
            makefile,
        )

    def test_local_quick_retains_compilation_and_shared_checks(self) -> None:
        result = subprocess.run(
            ["make", "--no-print-directory", "--dry-run", "ci-local-quick"],
            cwd=CI_YML.parents[2], capture_output=True, text=True, check=True,
        )
        for command in (
            "cargo fmt --all -- --check",
            "cargo check --all-targets --no-default-features --features pgp,license --locked",
            "cargo check --manifest-path fuzz/Cargo.toml --all-targets --locked",
            "python3 -m unittest discover -s scripts -p 'test_*.py'",
            "python3 tests/test_terminal_update_notice.py",
        ):
            self.assertEqual(result.stdout.count(command), 1, command)

    def test_workflow_recipe_executes_checks_and_propagates_failure(self) -> None:
        commands = [
            ["cargo", "fmt", "--all", "--", "--check"],
            ["python3", "-m", "unittest", "discover", "-s", "scripts", "-p", "test_*.py"],
            ["python3", "tests/test_benchmark_records.py"],
            ["python3", "tests/test_terminal_update_notice.py"],
            ["python3", "tests/test_audit_repair_shell.py"],
        ]
        for failed in range(len(commands) + 1):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "Makefile").write_bytes((CI_YML.parents[2] / "Makefile").read_bytes())
                (root / "scripts").mkdir()
                for name in ("install.sh", "benchmark-hyperfine.sh", "scripts/probe.sh"):
                    (root / name).write_text("exit 99\n", encoding="utf-8")
                runner = root / "record.py"
                runner.write_text(
                    "import json, os, pathlib, sys\n"
                    "log = pathlib.Path(os.environ['CHECK_LOG'])\n"
                    "rows = log.read_text().splitlines() if log.exists() else []\n"
                    "with log.open('a') as out: out.write(json.dumps(sys.argv[1:]) + '\\n')\n"
                    "sys.exit(17 if len(rows) + 1 == int(os.environ['FAIL_CHECK']) else 0)\n",
                    encoding="utf-8",
                )
                for command in ("cargo", "python3"):
                    stub = root / (command + (".cmd" if os.name == "nt" else ""))
                    if os.name == "nt":
                        content = f'@"{sys.executable}" "{runner}" {command} %*\n'
                    else:
                        content = f'#!/bin/sh\nexec "{sys.executable}" "{runner}" {command} "$@"\n'
                    stub.write_text(content, encoding="utf-8")
                    stub.chmod(0o755)
                log = root / "checks.jsonl"
                make = ["make", "--no-print-directory", "ci-workflow-quick"]
                if os.name == "nt":
                    make.append("SHELL=C:/Program Files/Git/bin/bash.exe")
                result = subprocess.run(
                    make, cwd=root,
                    env=dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                             CHECK_LOG=str(log), FAIL_CHECK=str(failed)),
                    capture_output=True, text=True, timeout=15,
                )
                self.assertEqual(result.returncode == 0, failed == 0, result.stderr)
                self.assertTrue(log.exists(), result.stderr)
                recorded = [json.loads(line) for line in log.read_text().splitlines()]
                self.assertEqual(recorded, commands[:failed or len(commands)])

    def test_arch_combination_has_one_platform_lane(self) -> None:
        text = CI_YML.read_text(encoding="utf-8")
        linux = job_block(text, "linux-matrix")
        intersections = job_block(text, "feature-intersections")
        self.assertIn("features: arch,pgp,license", linux)
        self.assertIn("cargo clippy --all-targets", linux)
        self.assertIn("python3 scripts/run-native-contracts.py --features ${{ matrix.features }}", linux)
        self.assertNotIn("features: arch,pgp,license", intersections)
        self.assertIn("features: debian,pgp\n", intersections)
        self.assertIn("cargo check --all-targets", intersections)


class ShellSyntaxGateTests(unittest.TestCase):
    def test_gate_checks_every_file_without_executing_scripts(self) -> None:
        makefile = CI_YML.parents[2] / "Makefile"
        scripts = [
            "install.sh",
            "benchmark-hyperfine.sh",
            "scripts/last.sh",
        ]
        for broken in [None, *scripts]:
            with (
                self.subTest(broken=broken),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                (root / "scripts").mkdir()
                for name in scripts:
                    content = (
                        "if then\n" if name == broken else "touch should-not-run\n"
                    )
                    (root / name).write_text(content, encoding="utf-8")
                result = subprocess.run(
                    [
                        "make",
                        "--no-print-directory",
                        "-f",
                        str(makefile),
                        "check-shell-syntax",
                    ],
                    cwd=root,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if broken is None:
                    self.assertEqual(result.returncode, 0, result.stderr)
                else:
                    self.assertNotEqual(result.returncode, 0, f"gate ignored {broken}")
                    self.assertIn(broken, result.stderr)
                self.assertFalse((root / "should-not-run").exists())


if __name__ == "__main__":
    unittest.main()
