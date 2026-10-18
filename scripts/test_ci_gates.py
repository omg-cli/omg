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
        self.assertNotIn("rust-toolchain@", gate)
        self.assertIn("components: rustfmt", job_block(text, "workflow-checks"))
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
                        expected.extend(["python3", "zsh", "fish"])
                    elif workflow == "qemu-matrix.yml":
                        expected.extend(["python3", "fish"])
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
                build_source = source
                if workflow.name == "qemu-matrix.yml":
                    build_source = "\n".join(
                        json.loads(encoded)
                        for encoded in re.findall(r'"setup":\s*("(?:\\.|[^"\\])*")', source)
                    )
                commands = re.findall(r"timeout -k 10s 12m dnf(?:[^\n]*\\\n)*[^\n]*", build_source)
                self.assertEqual(len(commands), expected)
                for command in commands:
                    self.assertEqual(command.count("--setopt='*.skip_if_unavailable=False'"), 1)
                self.assertNotIn("--setopt=fedora.metalink=", source)
                self.assertNotIn("--setopt=updates.metalink=", source)
                self.assertNotIn("--setopt=fedora.baseurl=", source)
                self.assertNotIn("--setopt=updates.baseurl=", source)
                self.assertEqual(source.count("timeout -k 10s 12m dnf"), expected)
                self.assertNotIn("dnf makecache --refresh", source)
                self.assertNotIn("--nogpgcheck", source)


    def test_fedora_fixture_provision_argv_and_failure_stop_helper(self) -> None:
        source = CI_YML.read_text(encoding="utf-8")
        step = source.split("      - name: Native Fedora ignored integration fixtures\n", 1)[1]
        step = step.split("\n      - name:", 1)[0]
        script = step.split("        run: |\n", 1)[1]
        script = "\n".join(line[10:] for line in script.splitlines())
        # Exercise provisioning, receipt accounting, and the helper gate together.
        script = "set -euo pipefail\nmkdir -p target/fedora-ignored\n" + script[script.index("started=$(date +%s)"):]
        script = script.replace("${{ matrix.features }}", "fedora,pgp,license")
        for exit_code in [0, 42]:
            with self.subTest(dnf_exit=exit_code):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / "dnf").write_text(
                        f"#!{sys.executable}\n"
                        "import json,os,sys\n"
                        "from pathlib import Path\n"
                        "Path(os.environ['DNF_CALL']).write_text(json.dumps(sys.argv[1:]))\n"
                        "sys.exit(int(os.environ['DNF_EXIT']))\n",
                        encoding="utf-8",
                    )
                    (root / "python3").write_text(
                        f"#!{sys.executable}\n"
                        "import os\nfrom pathlib import Path\n"
                        "Path(os.environ['HELPER_CALL']).write_text('helper reached')\n",
                        encoding="utf-8",
                    )
                    for name in ["dnf", "python3"]:
                        (root / name).chmod(0o755)
                    receipt = root / "call.json"
                    helper = root / "helper.txt"
                    result = subprocess.run(
                        ["bash", "-e", "-c", script],
                        cwd=root,
                        env=dict(os.environ, PATH=f"{root}:{os.environ['PATH']}",
                                 DNF_CALL=str(receipt), DNF_EXIT=str(exit_code), HELPER_CALL=str(helper)),
                        capture_output=True, text=True, timeout=10, check=False,
                    )
                    self.assertEqual(result.returncode, exit_code, result.stderr)
                    self.assertEqual(json.loads(receipt.read_text(encoding="utf-8")), [
                        "--setopt=*.skip_if_unavailable=False", "install", "-y",
                        "--setopt=install_weak_deps=False", "tree", "createrepo_c", "gnupg2",
                    ])
                    provision = json.loads((root / "target/fedora-ignored/provision.json").read_text(encoding="utf-8"))
                    self.assertEqual(provision["exit_code"], exit_code)
                    self.assertGreaterEqual(provision["elapsed_seconds"], 0)
                    if exit_code == 0:
                        self.assertEqual(helper.read_text(encoding="utf-8"), "helper reached")
                    else:
                        self.assertFalse(helper.exists(), "failed provisioning must stop before the helper")


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
        gate = job_block(text, "workflow-checks")
        self.assertNotIn(
            "make -n",
            gate,
            "workflow checks must not use `make -n` dry-run: it never executes recipes",
        )
        self.assertRegex(
            gate,
            r"run:\s*make ci-workflow-quick",
            "workflow checks must really execute `make ci-workflow-quick`",
        )


class CiDeduplicationTests(unittest.TestCase):
    def test_workflow_checks_execute_shared_checks_only_once(self) -> None:
        gate = job_block(CI_YML.read_text(encoding="utf-8"), "workflow-checks")
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
            ["python3", "-m", "unittest", "discover", "-s", "scripts", "-p", "test_*.py", "-v"],
            ["python3", "tests/test_benchmark_records.py"],
            ["python3", "tests/test_terminal_update_notice.py"],
            ["python3", "tests/test_audit_repair_shell.py"],
            ["python3", "-B", "-m", "unittest", "discover", "-s", "tests",
             "-p", "test_changelog_workflow_security.py", "-v"],
            ["python3", "-B", "-m", "unittest", "discover", "-s", "tests",
             "-p", "test_ci_config_path_security.py", "-v"],
            ["python3", "-B", "-m", "unittest", "discover", "-s", "tests",
             "-p", "test_container_path_security.py", "-v"],
            ["python3", "-B", "-m", "unittest", "discover", "-s", "tests",
             "-p", "test_daemon_path_security.py", "-v"],
            ["python3", "-B", "-m", "unittest", "discover", "-s", "tests",
             "-p", "test_shell_backup_safety.py", "-v"],
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


class OwnerInventoryError(AssertionError):
    pass


class NormalPrOriginalOwners(unittest.TestCase):
    EXPECTED = [
        [
            "cargo", "test", "--test", "distro_override", "--no-default-features",
            "--features", "pgp,license", "--locked",
        ],
        [
            "cargo", "test", "--release", "--test", "distro_override",
            "--no-default-features", "--features", "pgp,license", "--locked",
        ],
        [
            "cargo", "test", "--doc", "--no-default-features", "--features",
            "pgp,license", "--locked",
        ],
    ]

    @staticmethod
    def owners(text: str) -> list[tuple[str, str, list[str]]]:
        import shlex

        block = job_block(text, "portable")
        steps = re.split(r"(?=^      - )", block, flags=re.M)
        commands: list[tuple[str, str, list[str]]] = []
        for step in steps:
            run = re.search(r"^        run: (cargo .+)$", step, re.M)
            if not run:
                continue
            argv = shlex.split(run[1])
            if "--doc" in argv or (
                "--test" in argv
                and argv[argv.index("--test") + 1] == "distro_override"
            ):
                if re.search(r"^        (if:|continue-on-error:)", step, re.M):
                    raise OwnerInventoryError(
                        "Owner has independent conditional/error suppression"
                    )
                commands.append((step, run[1], argv))
        keys = [
            "docs" if "--doc" in argv else "release" if "--release" in argv else "debug"
            for _, _, argv in commands
        ]
        if keys != ["debug", "release", "docs"]:
            raise OwnerInventoryError(
                "Missing/duplicate/reordered original owner inventory: " + repr(keys)
            )
        return commands

    def test_selected_original_owners_execute_literal_argv_and_stop_each_failure(self) -> None:
        commands = self.owners(CI_YML.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = root / "record.py"
            record.write_text(
                'import json,os,pathlib,sys\n'
                'p=pathlib.Path(os.environ["OWNER_LOG"])\n'
                'rows=p.read_text().splitlines() if p.exists() else []\n'
                'with p.open("a") as f:f.write(json.dumps(["cargo"]+sys.argv[1:])+"\\n")\n'
                'sys.exit(23 if len(rows)+1==int(os.environ["FAIL_OWNER"]) else 0)\n',
                encoding="utf-8",
            )
            cargo = root / "cargo"
            cargo.write_text(
                f'#!/bin/sh\nexec "{sys.executable}" "{record}" "$@"\n',
                encoding="utf-8",
            )
            cargo.chmod(0o755)
            log = root / "rows.jsonl"
            for failed in (0, 1, 2, 3):
                with self.subTest(failed=failed):
                    log.unlink(missing_ok=True)
                    result = subprocess.run(
                        ["bash", "-e", "-c", "\n".join(x[1] for x in commands)],
                        env=dict(
                            os.environ,
                            PATH=str(root) + os.pathsep + os.environ["PATH"],
                            OWNER_LOG=str(log),
                            FAIL_OWNER=str(failed),
                        ),
                        capture_output=True,
                        timeout=10,
                    )
                    self.assertEqual(result.returncode, 0 if failed == 0 else 23, result.stderr)
                    self.assertEqual(
                        [json.loads(x) for x in log.read_text().splitlines()],
                        self.EXPECTED[:failed or 3],
                    )

    def test_missing_each_named_owner_refuses_even_when_other_owners_succeed(self) -> None:
        text = CI_YML.read_text(encoding="utf-8")
        commands = self.owners(text)
        for step, _, _ in commands:
            with self.subTest(omitted=step.splitlines()[0]):
                with self.assertRaises(OwnerInventoryError):
                    self.owners(text.replace(step, "", 1))

    def test_original_source_paths_select_normal_pr_owner_using_real_git_diff(self) -> None:
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "actual_scope", Path(__file__).with_name("ci-change-scope.py")
        )
        assert spec is not None and spec.loader is not None
        scope = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(scope)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*args: str) -> str:
                return subprocess.check_output(
                    [
                        "git", "-c", "maintenance.auto=false", "-c", "gc.auto=0",
                        "-c", "user.name=Owner Fixture", "-c",
                        "user.email=fixture@example.invalid", *args,
                    ],
                    cwd=root,
                ).decode().strip()

            git("init", "-q")
            (root / "README.md").write_text("base", encoding="utf-8")
            git("add", ".")
            git("commit", "-qm", "baseline")
            base = git("rev-parse", "HEAD")
            for name, expected in [
                ("tests/distro_override.rs", True),
                ("src/core/env/distro.rs", True),
                ("src/core/client.rs", True),
                ("src/core/sudoloop.rs", True),
                ("src/cli/tea/mod.rs", True),
                ("README.md", False),
            ]:
                with self.subTest(path=name):
                    git("checkout", "-q", "--detach", base)
                    path = root / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("changed", encoding="utf-8")
                    git("add", ".")
                    git("commit", "-qm", name)
                    event = {
                        "pull_request": {
                            "base": {"sha": base},
                            "head": {"sha": git("rev-parse", "HEAD")},
                        }
                    }
                    self.assertEqual(scope.changed_paths(event, root), [name])
                    self.assertEqual(
                        scope.classify_scope("pull_request", event, root),
                        (expected, expected),
                    )


if __name__ == "__main__":
    unittest.main()
