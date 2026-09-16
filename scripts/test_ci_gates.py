# pyright: strict
from __future__ import annotations

import re
import subprocess
import tempfile
import unittest
from pathlib import Path

CI_YML = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "ci.yml"


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
            f"quick-gate timeout must stay <= 10 min: the gate really "
            f"executes make ci-local-quick (~4.5 min cold), got {m.group(1)}",
        )
        self.assertIn(
            "Swatinem/rust-cache",
            gate,
            "quick-gate must restore the Rust cache or every run pays a "
            "cold 4+ minute check and the gate is not quick at all",
        )
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
            r"run:\s*make ci-local-quick",
            "quick-gate must really execute `make ci-local-quick`",
        )


class CiDeduplicationTests(unittest.TestCase):
    def test_quick_gate_executes_shared_checks_only_once(self) -> None:
        gate = job_block(CI_YML.read_text(encoding="utf-8"), "quick-gate")
        self.assertEqual(gate.count("run: make ci-local-quick"), 1)
        result = subprocess.run(
            ["make", "--no-print-directory", "--dry-run", "ci-local-quick"],
            cwd=CI_YML.parents[2],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        for command in [
            "cargo fmt --all -- --check",
            "python3 -m unittest discover -s scripts -p 'test_*.py'",
        ]:
            with self.subTest(command=command):
                self.assertNotIn(command, gate)
                self.assertEqual(result.stdout.count(command), 1)
        self.assertNotIn("run: make check-shell-syntax", gate)
        self.assertEqual(result.stdout.count("bash -n"), 1)

    def test_portable_keeps_tests_and_lints_without_repeating_gate_compilation(
        self,
    ) -> None:
        portable = job_block(CI_YML.read_text(encoding="utf-8"), "portable")
        self.assertIn("needs: quick-gate", portable)
        self.assertNotIn("cargo check", portable)
        self.assertIn("cargo clippy --all-targets", portable)
        self.assertIn("--features debian-pure", portable)
        self.assertIn("cargo nextest run --lib", portable)
        makefile = (CI_YML.parents[2] / "Makefile").read_text(encoding="utf-8")
        self.assertIn(
            "cargo check --manifest-path fuzz/Cargo.toml --all-targets --locked",
            makefile,
        )

    def test_arch_combination_has_one_platform_lane(self) -> None:
        text = CI_YML.read_text(encoding="utf-8")
        linux = job_block(text, "linux-matrix")
        intersections = job_block(text, "feature-intersections")
        self.assertIn("features: arch,pgp,license", linux)
        self.assertIn("cargo clippy --all-targets", linux)
        self.assertIn("cargo nextest run --lib", linux)
        self.assertNotIn("features: arch,pgp,license", intersections)
        self.assertIn("features: debian,pgp\n", intersections)
        self.assertIn("cargo check --all-targets", intersections)


class ShellSyntaxGateTests(unittest.TestCase):
    def test_gate_checks_every_file_without_executing_scripts(self) -> None:
        makefile = CI_YML.parents[2] / "Makefile"
        scripts = [
            "install.sh",
            "benchmark.sh",
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
