"""Regression checks for unbiased Hyperfine evidence admission."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Protocol, cast


class Recorder(Protocol):
    def validate_results(self, source: Path) -> list[str]: ...

    def daemon_result(self, payload: dict[str, object]) -> dict[str, object] | None: ...

    def native_result(self, payload: dict[str, object]) -> dict[str, object] | None: ...

    def render_latest_md(self, meta: dict[str, object], source: Path) -> str: ...

    def summarize_scenario(self, data: object) -> list[dict[str, object]]: ...


def meta_fixture() -> dict[str, object]:
    return {
        "id": "fixture",
        "timestamp": "fixture",
        "git": {"commit": "fixture", "describe": "fixture", "dirty": False},
        "host": {
            "cpu": "fixture",
            "machine": "fixture",
            "release": "fixture",
            "ram_gib": 1,
        },
    }


def load_recorder() -> Recorder:
    path = Path(__file__).resolve().parents[1] / "scripts/record-benchmark-run.py"
    spec = importlib.util.spec_from_file_location("benchmark_recorder", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot load benchmark recorder")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return cast(Recorder, module)


def measurement(name: str, seconds: float) -> dict[str, object]:
    return {
        "command": name,
        "mean": seconds,
        "median": seconds,
        "min": seconds,
        "max": seconds,
        "stddev": 0.0,
        "user": 0.0,
        "system": 0.0,
        "times": [seconds, seconds],
        "exit_codes": [0, 0],
    }


class BenchmarkAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="benchmark-record-test-")
        self.addCleanup(self.directory.cleanup)
        self.source = Path(self.directory.name)
        self.recorder = load_recorder()

    def write_results(self, *results: dict[str, object]) -> None:
        (self.source / "search.json").write_text(
            json.dumps({"results": results}), encoding="utf-8"
        )

    def test_summary_keeps_single_sample_deviation_unknown(self) -> None:
        result = measurement("OMG", 0.25)
        result.update(times=[0.25], exit_codes=[0], stddev=None)
        rows = self.recorder.summarize_scenario({"results": [result]})
        self.assertEqual(rows[0]["stddev_ms"], None)
        self.assertEqual(rows[0]["mean_ms"], 250.0)
        self.assertEqual(rows[0]["runs"], 1)

    def test_summary_preserves_slower_results_and_actual_labels(self) -> None:
        rows = self.recorder.summarize_scenario(
            {"results": [measurement("OMG", 0.2), measurement("apt", 0.1)]}
        )
        self.assertEqual([row["command"] for row in rows], ["OMG", "apt"])
        self.assertEqual([row["mean_ms"] for row in rows], [200.0, 100.0])

    def test_summary_rejects_fabricated_statistics(self) -> None:
        result = measurement("OMG", 0.2)
        result["mean"] = 0.001
        with self.assertRaisesRegex(ValueError, "mean does not match"):
            self.recorder.summarize_scenario({"results": [result]})

    def test_summary_rejects_failed_receipts(self) -> None:
        result = measurement("OMG", 0.2)
        result["exit_codes"] = [0, 1]
        with self.assertRaisesRegex(ValueError, "non-zero exit"):
            self.recorder.summarize_scenario({"results": [result]})

    def test_summary_rejects_missing_measurements(self) -> None:
        with self.assertRaisesRegex(ValueError, "no measurements"):
            self.recorder.summarize_scenario({"results": []})

    def test_summary_rejects_duplicate_labels(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate command"):
            self.recorder.summarize_scenario(
                {"results": [measurement("OMG", 0.1), measurement("OMG", 0.2)]}
            )

    def test_summary_rejects_unit_conversion_overflow(self) -> None:
        result = measurement("OMG", 0.2)
        result["user"] = 1e308
        with self.assertRaisesRegex(ValueError, "finite"):
            self.recorder.summarize_scenario({"results": [result]})

    def test_transaction_mode_refuses_unmarked_host(self) -> None:
        script = Path(__file__).resolve().parents[1] / "benchmark-hyperfine.sh"
        result = subprocess.run(
            ["/bin/bash", str(script), "--guest-transaction", "install", "omg"],
            cwd=self.source,
            env={
                **os.environ,
                "OMG_BENCH_DISPOSABLE_GUEST": "",
                "OMG_BENCH_EXPORT_DIR": str(self.source / "output"),
            },
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("marked disposable QEMU guest", result.stderr)
        self.assertFalse((self.source / "output").exists())

    def test_transaction_mode_rejects_unknown_operation(self) -> None:
        script = Path(__file__).resolve().parents[1] / "benchmark-hyperfine.sh"
        result = subprocess.run(
            ["/bin/bash", str(script), "--guest-transaction", "upgrade", "omg"],
            cwd=self.source,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("install or remove", result.stderr)

    def test_transaction_count_is_bounded_before_guest_start(self) -> None:
        script = Path(__file__).resolve().parents[1] / "scripts/benchmark-qemu.sh"
        for count in ("0", "101", "-1", "1;exit 0"):
            result = subprocess.run(
                ["/bin/bash", str(script), "--benchmark-transactions", count],
                cwd=self.source,
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_guest_and_development_modes_are_exclusive(self) -> None:
        script = Path(__file__).resolve().parents[1] / "benchmark-hyperfine.sh"
        result = subprocess.run(
            ["/bin/bash", str(script), "--guest", "--update"],
            cwd=self.source,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("mutually exclusive", result.stderr)

    def test_command_metadata_preserves_every_argument(self) -> None:
        script = Path(__file__).resolve().parents[1] / "benchmark-hyperfine.sh"
        body = script.read_text(encoding="utf-8").split("command_json() {\n", 1)[1]
        body = body.split("\n}\n", 1)[0]
        invocation = "command_json() {\n" + body + '\n}\ncommand_json "$@"\n'
        arguments = [
            "program",
            "with spaces",
            "--flag",
            "",
            "quote'\"value",
            "line\nbreak",
        ]
        result = subprocess.run(
            ["/bin/bash", "-s", "--", "fixture label", *arguments],
            input=invocation,
            cwd=self.source,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload: object = json.loads(result.stdout)
        self.assertEqual(payload, {"label": "fixture label", "argv": arguments})

    def test_single_transaction_sample_requires_successful_exit(self) -> None:
        script = Path(__file__).resolve().parents[1] / "scripts/record-benchmark-run.py"
        sample = measurement("OMG", 0.1)
        sample.update(times=[0.1], exit_codes=[0], stddev=None)
        for scenario in ("install", "remove"):
            path = self.source / f"{scenario}.json"
            for exit_code in (0, 7):
                sample["exit_codes"] = [exit_code]
                path.write_text(json.dumps({"results": [sample]}), encoding="utf-8")
                result = subprocess.run(
                    [
                        sys.executable,
                        str(script),
                        "--validate-only",
                        "--scenario",
                        scenario,
                        "--source",
                        str(self.source),
                    ],
                    cwd=self.source,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )
                self.assertEqual(
                    result.returncode,
                    0 if exit_code == 0 else 1,
                    result.stdout + result.stderr,
                )
            path.unlink()

    def test_scoped_validation_does_not_create_records(self) -> None:
        scripts = self.source / "scripts"
        scripts.mkdir()
        original = (
            Path(__file__).resolve().parents[1] / "scripts/record-benchmark-run.py"
        )
        script = scripts / original.name
        shutil.copyfile(original, script)
        self.write_results(measurement("OMG", 0.1), measurement("rpm", 0.01))
        (self.source / "search.json").rename(self.source / "info.json")
        result = subprocess.run(
            [
                sys.executable,
                str(script),
                "--validate-only",
                "--scenario",
                "info",
                "--source",
                str(self.source),
            ],
            cwd=self.source,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.source / "benchmarks").exists())

    def test_rejects_malformed_json_without_exception(self) -> None:
        (self.source / "search.json").write_text("{", encoding="utf-8")
        self.assertTrue(self.recorder.validate_results(self.source))

    def test_rejects_oversized_measurement_file(self) -> None:
        (self.source / "search.json").write_bytes(b" " * 1048577)
        self.assertTrue(self.recorder.validate_results(self.source))

    def test_missing_hyperfine_never_runs_substitute_timer(self) -> None:
        tools = self.source / "tools"
        tools.mkdir()
        for name in ("dirname", "mkdir"):
            executable = shutil.which(name)
            if executable is None:
                raise RuntimeError(f"Missing fixture prerequisite: {name}")
            (tools / name).symlink_to(executable)
        fallback = self.source / "benchmark.sh"
        fallback.write_text("#!/bin/sh\nexit 77\n", encoding="utf-8")
        fallback.chmod(0o700)
        environment = {
            **os.environ,
            "HOME": str(self.source / "home"),
            "PATH": str(tools),
            "OMG_BENCH_EXPORT_DIR": str(self.source / "output"),
        }
        script = Path(__file__).resolve().parents[1] / "benchmark-hyperfine.sh"
        result = subprocess.run(
            ["/bin/bash", str(script), "--fast"],
            cwd=self.source,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("no substitute timer", result.stderr)

    def test_guest_mode_refuses_implicit_source_build(self) -> None:
        tools = self.source / "tools"
        tools.mkdir()
        for name in ("dirname", "mkdir", "jq"):
            executable = shutil.which(name)
            if executable is None:
                raise RuntimeError(f"Missing fixture prerequisite: {name}")
            (tools / name).symlink_to(executable)
        for name in ("cargo", "hyperfine"):
            stub = tools / name
            stub.write_text("#!/bin/sh\nexit 77\n", encoding="utf-8")
            stub.chmod(0o700)
        environment = {
            **os.environ,
            "HOME": str(self.source / "home"),
            "PATH": str(tools),
            "OMG_BENCH_BINARY": "",
            "OMG_BENCH_EXPORT_DIR": str(self.source / "output"),
        }
        script = Path(__file__).resolve().parents[1] / "benchmark-hyperfine.sh"
        result = subprocess.run(
            ["/bin/bash", str(script), "--guest"],
            cwd=self.source,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("prebuilt binary", result.stderr)

    def test_full_run_does_not_hide_update_benchmark_failure(self) -> None:
        tools = self.source / "tools"
        tools.mkdir()
        for name in (
            "dirname",
            "mkdir",
            "mktemp",
            "chmod",
            "rm",
            "seq",
            "grep",
            "cat",
            "wc",
            "tr",
            "python3",
            "tail",
            "jq",
        ):
            executable = shutil.which(name)
            if executable is None:
                raise RuntimeError(f"Missing fixture prerequisite: {name}")
            (tools / name).symlink_to(executable)
        stubs = {
            "omg": '#!/bin/bash\ncase "$1" in ec) echo 1;; *) echo firefox;; esac\n',
            "omgd": "#!/bin/bash\nexec /usr/bin/sleep 60\n",
            "hyperfine": '#!/bin/bash\nwhile [[ $# -gt 0 ]]; do\n  if [[ $1 == --export-json ]]; then printf \'{"results":[]}\\n\' > "$2"; break; fi\n  shift\ndone\n',
        }
        for name, content in stubs.items():
            path = tools / name
            path.write_text(content, encoding="utf-8")
            path.chmod(0o700)
        environment = {
            **os.environ,
            "HOME": str(self.source / "home"),
            "PATH": str(tools),
            "OMG_BENCH_BINARY": str(tools / "omg"),
            "OMG_BENCH_EXPORT_DIR": str(self.source / "output"),
            "OMG_BENCH_SOURCE_CACHE": str(self.source / "absent-cache"),
            "OMG_BENCH_SKIP_UPDATE": "0",
            "OMG_BENCH_SKIP_RECORD": "1",
        }
        script = Path(__file__).resolve().parents[1] / "benchmark-hyperfine.sh"
        result = subprocess.run(
            ["/bin/bash", str(script)],
            cwd=self.source,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        # Root execution is also deliberately refused before update discovery.
        self.assertTrue(
            "Missing benchmark fixture" in result.stderr
            or "Run the update benchmark as a regular user" in result.stderr,
            result.stdout + result.stderr,
        )
        self.assertNotIn("Benchmarks Complete!", result.stdout)

    def test_retains_slower_results(self) -> None:
        self.write_results(measurement("OMG (Daemon)", 0.3), measurement("pacman", 0.1))
        self.assertEqual(self.recorder.validate_results(self.source), [])

    def test_retains_parity(self) -> None:
        self.write_results(measurement("OMG (Daemon)", 0.1), measurement("pacman", 0.1))
        self.assertEqual(self.recorder.validate_results(self.source), [])

    def test_no_arbitrary_time_or_cpu_floor(self) -> None:
        self.write_results(
            measurement("OMG (Daemon)", 0.00001), measurement("pacman", 0.00002)
        )
        self.assertEqual(self.recorder.validate_results(self.source), [])

    def test_accepts_actual_driver_command_label(self) -> None:
        self.write_results(measurement("OMG", 0.1), measurement("pacman", 0.2))
        self.assertEqual(self.recorder.validate_results(self.source), [])

    def test_rejects_failed_sample(self) -> None:
        result = measurement("OMG (Daemon)", 0.1)
        result["exit_codes"] = [0, 1]
        self.write_results(result)
        self.assertTrue(self.recorder.validate_results(self.source))

    def test_rejects_missing_exit_receipt(self) -> None:
        result = measurement("OMG (Daemon)", 0.1)
        result["exit_codes"] = [0]
        self.write_results(result)
        self.assertTrue(self.recorder.validate_results(self.source))

    def test_rejects_nonfinite_sample(self) -> None:
        result = measurement("OMG (Daemon)", 0.1)
        result["times"] = [0.1, float("nan")]
        self.write_results(result)
        self.assertTrue(self.recorder.validate_results(self.source))

    def test_rejects_fabricated_summary(self) -> None:
        result = measurement("OMG (Daemon)", 0.1)
        result["times"] = [0.2, 0.2]
        self.write_results(result)
        self.assertTrue(self.recorder.validate_results(self.source))

    def test_rejects_boolean_exit_code(self) -> None:
        result = measurement("OMG (Daemon)", 0.1)
        result["exit_codes"] = [False, False]
        self.write_results(result)
        self.assertTrue(self.recorder.validate_results(self.source))


class QemuCloudInitTests(unittest.TestCase):
    def setUp(self) -> None:
        script = Path(__file__).resolve().parents[1] / "scripts/benchmark-qemu.sh"
        self.text = script.read_text(encoding="utf-8")
        self.bash = os.environ.get("OMG_TEST_BASH") or "/bin/bash"

    def test_generated_seed_preserves_hostname_and_pins_host_key(self) -> None:
        seed = self.text.split("ssh-keygen -q -t ed25519 -N '' -f guest-host-key\n", 1)[1]
        seed = seed.split("cloud-localds seed.img user-data meta-data", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "client-key.pub").write_text("ssh-ed25519 fixture-client\n")
            (root / "guest-host-key").write_text("fixture-private-key\n")
            (root / "guest-host-key.pub").write_text("ssh-ed25519 fixture-host\n")
            result = subprocess.run(
                [self.bash, "-euo", "pipefail", "-c", seed],
                cwd=root, capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("\npreserve_hostname: true\n", (root / "user-data").read_text())
            seed_text = (root / "user-data").read_text()
            self.assertIn("path: /etc/systemd/system/omg-boot-network.service", seed_text)
            self.assertIn("TTYPath=/dev/ttyS0", seed_text)
            self.assertIn("TimeoutStartSec=15", seed_text)
            self.assertIn("--unit=systemd-networkd --unit=NetworkManager --lines=80", seed_text)
            self.assertIn("OnBootSec=45", seed_text)
            self.assertIn("Unit=omg-boot-network.service", seed_text)
            self.assertNotIn("local-hostname", (root / "meta-data").read_text())
            self.assertEqual(
                (root / "known_hosts").read_text(),
                "[127.0.0.1]:2222 ssh-ed25519 fixture-host\n",
            )

    def test_guest_probe_runs_after_cloud_init_gate_and_keeps_failures_fatal(self) -> None:
        gate = 'bash /work/check-qemu-cloud-init.sh bench@127.0.0.1 "${opts[@]}"'
        probe = next(line for line in self.text.splitlines()
                     if line.startswith("if timeout ") and "os-release" in line)
        self.assertLess(self.text.index(gate), self.text.index(probe))
        command = probe.removeprefix("if ").removesuffix("; then :; else")
        arguments = shlex.split(command)
        self.assertEqual(arguments[:4], [
            "timeout", "--kill-after=${BOOT_PHASE_KILL_GRACE}s",
            "${BOOT_IDENTITY_TIMEOUT}s", "ssh",
        ])
        remote = arguments[-1]
        mocks = """
cat() { printf 'guest-os\n'; }
uname() { printf 'guest-kernel\n'; }
sudo() { printf 'sudo-ok\n'; return "$SUDO_STATUS"; }
"""
        for status in (0, 1):
            with self.subTest(status=status):
                result = subprocess.run(
                    [self.bash, "-c", mocks + remote],
                    env=dict(os.environ, SUDO_STATUS=str(status)),
                    capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertIn("guest-os", result.stdout)
                self.assertIn("guest-kernel", result.stdout)
                self.assertIn("sudo-ok", result.stdout)
        phase = self.text.split(probe, 1)[1].split("fi\n", 1)[0]
        for status in (0, 1, 124):
            with self.subTest(phase_status=status):
                result = subprocess.run(
                    [self.bash, "-c", """
BOOT_PHASE_KILL_GRACE=2
BOOT_IDENTITY_TIMEOUT=15
opts=()
timeout() { return "$PROBE_STATUS"; }
""" + probe + phase + "fi\n"],
                    env=dict(os.environ, PROBE_STATUS=str(status)),
                    capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(result.returncode, status, result.stderr)
                if status:
                    self.assertIn(f"Boot identity failed: exit={status}", result.stderr)


class HeadlineResolutionTests(unittest.TestCase):
    """Headline extraction must match the labels benchmark-hyperfine.sh emits."""

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="benchmark-record-test-")
        self.addCleanup(self.directory.cleanup)
        self.source = Path(self.directory.name)
        self.recorder = load_recorder()

    def write_results(self, *results: dict[str, object]) -> None:
        (self.source / "search.json").write_text(
            json.dumps({"results": list(results)}), encoding="utf-8"
        )

    def test_current_omg_label_resolves_daemon_result(self) -> None:
        payload = cast(
            dict[str, object],
            json.loads(
                json.dumps(
                    {"results": [measurement("OMG", 0.2), measurement("pacman", 0.4)]}
                )
            ),
        )
        daemon = self.recorder.daemon_result(payload)
        self.assertIsNotNone(daemon)
        self.assertAlmostEqual(cast(dict[str, object], daemon)["mean"], 0.2)  # type: ignore[arg-type]

    def test_legacy_omg_label_still_resolves(self) -> None:
        payload = cast(
            dict[str, object],
            json.loads(
                json.dumps(
                    {
                        "results": [
                            measurement("OMG (Daemon)", 0.2),
                            measurement("pacman", 0.4),
                        ]
                    }
                )
            ),
        )
        daemon = self.recorder.daemon_result(payload)
        self.assertIsNotNone(daemon)

    def test_native_result_is_not_the_omg_driver(self) -> None:
        payload = cast(
            dict[str, object],
            json.loads(
                json.dumps(
                    {
                        "results": [
                            measurement("OMG", 0.2),
                            measurement("dnf", 0.5),
                        ]
                    }
                )
            ),
        )
        native = self.recorder.native_result(payload)
        self.assertIsNotNone(native)
        self.assertEqual(cast(dict[str, object], native)["command"], "dnf")

    def test_render_uses_current_label(self) -> None:
        self.write_results(measurement("OMG", 0.2), measurement("pacman", 0.4))
        rendered = self.recorder.render_latest_md(meta_fixture(), self.source)
        self.assertIn("Daemon mean **200.0 ms**", rendered)
        self.assertIn("pacman **400.0 ms**", rendered)

    def test_transaction_capture_preserves_exit_and_both_streams(self) -> None:
        if os.name != "posix":
            self.skipTest("QEMU guest transaction capture requires POSIX")
        bash = shutil.which("bash")
        self.assertIsNotNone(bash)
        script = Path(__file__).resolve().parents[1] / "benchmark-hyperfine.sh"
        stdout = self.source / "transaction.stdout"
        stderr = self.source / "transaction.stderr"
        result = subprocess.run(
            [bash, str(script), "--capture-transaction", str(stdout), str(stderr),
             bash, "-c", 'printf "install started\\n"; printf "native failure\\n" >&2; exit 17'],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 17, result.stderr)
        self.assertEqual(stdout.read_text(), "install started\n")
        self.assertEqual(stderr.read_text(), "native failure\n")
        self.assertEqual((result.stdout, result.stderr), ("", ""))



class FedoraBenchmarkIdentityTests(unittest.TestCase):
    # Exact streams from run37047627326/attempt1 artifact11246206635,
    # server-bound ZIP SHA4563fa20d3ee5731cf8114a407127d2e410b0e2ecca1a43964c8015f7eeb91d5.
    PRODUCT = '\n  | Info\n    tree.x86_64\n          Name: tree.x86_64\n       Version: 2.2.1-4.fc44\n        Source: Official repository (dnf)\n     Installed: yes\n   Description: File system tree viewer\n'
    NATIVE = 'Name        : tree\nVersion     : 2.2.1\nRelease     : 4.fc44\nArchitecture: x86_64\nInstall Date: Fri Oct  2 18:46:45 2026\nGroup       : Unspecified\nSize        : 122910\nLicense     : GPL-2.0-or-later AND LGPL-2.1-or-later\nSignature   :\n              RSA/SHA256, Mon Jan 19 08:40:13 2026, Key ID dbfcf71c6d9f90a6\nSource RPM  : tree-pkg-2.2.1-4.fc44.src.rpm\nBuild Date  : Sun Jan 18 22:06:31 2026\nBuild Host  : buildvm-x86-10.rdu3.fedoraproject.org\nPackager    : Fedora Project\nVendor      : Fedora Project\nURL         : https://oldmanprogrammer.net/source.php?dir=projects/tree\nBug URL     : https://bugz.fedoraproject.org/tree-pkg\nSummary     : File system tree viewer\nDescription :\nThe tree utility recursively displays the contents of directories in a\ntree-like format.  Tree is basically a UNIX port of the DOS tree\nutility.\n'

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="fedora-benchmark-info-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.script = Path(__file__).resolve().parents[1] / "benchmark-hyperfine.sh"

    def definition(self, name: str) -> str:
        text = self.script.read_text(encoding="utf-8")
        marker = "    " + name + "() {\n"
        if marker not in text:
            return ""
        body = text.split(marker, 1)[1].split("\n    }\n", 1)[0]
        return name + "() {\n" + body + "\n}\n"

    def search_result(self, value: str, native: bool = False, distro: str = "fedora",
                      arch: str = "x86_64", kind: str = "search") -> subprocess.CompletedProcess[str]:
        path = self.directory / "search-input.txt"
        path.write_text(value, encoding="utf-8")
        invocation = ('set -euo pipefail\ndistro=$1\nhost_arch=$2\n'
                      'uname() { printf "%s\\n" "$host_arch"; }\n'
                      + self.definition("omg_names") + self.definition("search_names")
                      + ('search_names dnf "$3"\n' if native else 'omg_names "$4" "$3"\n'))
        return subprocess.run(["/bin/bash", "-s", "--", distro, arch, str(path), kind],
                              input=invocation, cwd=self.directory, capture_output=True,
                              text=True, check=False, timeout=10)

    def test_recorded_fedora_search_reaches_required_package_and_native_equivalence(self) -> None:
        # Run38009788242 artifact11652634624, ZIP SHA0ce89c5d02105ab9205a08214480df7d6697623b7a41a59cc26b89af67fe4113.
        product = json.dumps([{"name": name} for name in
                              ("ripgrep-edit-emacs.noarch", "ripgrep-edit.x86_64", "ripgrep.x86_64")])
        native = ("Matched fields: name (exact)\n ripgrep.x86_64\tLine-oriented search tool\n"
                  "Matched fields: name, summary\n ripgrep-edit.x86_64\tEdit ripgrep search results across multiple files\n"
                  " ripgrep-edit-emacs.noarch\tUse Emacs to edit ripgrep search results across multiple files\n")
        expected = "ripgrep\nripgrep-edit\nripgrep-edit-emacs\n"
        for value, is_native in ((product, False), (native, True)):
            with self.subTest(native=is_native):
                result = self.search_result(value, is_native)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, expected)
                self.assertIn("ripgrep", result.stdout.splitlines())

    def test_fedora_search_preserves_dotted_names_and_deduplicates_host_and_noarch(self) -> None:
        value = json.dumps([{"name": name} for name in
                            ("ripgrep.aarch64", "ripgrep.noarch", "ripgrep.plugin.aarch64")])
        result = self.search_result(value, arch="aarch64")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "ripgrep\nripgrep.plugin\n")

    def test_fedora_search_refuses_foreign_or_unqualified_names_before_output(self) -> None:
        for name in ("ripgrep.i686", "ripgrep.aarch64", "ripgrep", "ripgrep.x86-64", ".x86_64"):
            with self.subTest(name=name):
                value = json.dumps([{"name": "ripgrep.x86_64"}, {"name": name}])
                result = self.search_result(value)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertEqual(result.stdout, "")

    def test_search_refuses_empty_malformed_and_potentially_truncated_product_sets(self) -> None:
        for value in ("[]", "{}", '[{"name": null}]', '[{"name": "bad name"}]', "[",
                      json.dumps([{"name": "ripgrep.x86_64"}] * 100000)):
            with self.subTest(length=len(value)):
                result = self.search_result(value)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertEqual(result.stdout, "")

    def test_other_distro_and_explicit_name_sets_retain_existing_identity(self) -> None:
        for distro in ("arch", "debian", "ubuntu"):
            result = self.search_result('[{"name":"ripgrep.plugin.x86_64"}]', distro=distro)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "ripgrep.plugin.x86_64\n")
        result = self.search_result('{"packages":["ripgrep.plugin","ripgrep.x86_64"]}', kind="explicit")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "ripgrep.plugin\nripgrep.x86_64\n")

    def normalize(self, value: str, native: bool = False, phase: str = "installed",
                  arch: str = "x86_64", evr: str = "2.2.1-4.fc44") -> subprocess.CompletedProcess[str]:
        path = self.directory / "input.txt"
        path.write_text(value, encoding="utf-8")
        return subprocess.run(
            ["/bin/bash", "-s", "--", "true" if native else "false", str(path), phase, arch, evr],
            input="set -euo pipefail\ndistro=fedora\n" + self.definition("normalize_info") + 'normalize_info "$@"\n',
            cwd=self.directory, capture_output=True, text=True, check=False, timeout=10,
        )

    def query(self, value: str, phase: str = "installed", arch: str = "x86_64",
              evr: str = "") -> subprocess.CompletedProcess[str]:
        path = self.directory / "query.txt"
        path.write_text(value, encoding="utf-8")
        return subprocess.run(
            ["/bin/bash", "-s", "--", str(path), phase, arch, evr],
            input="set -euo pipefail\n" + self.definition("fedora_identity_from_query") + 'fedora_identity_from_query "$@"\n',
            cwd=self.directory, capture_output=True, text=True, check=False, timeout=10,
        )

    def test_recorded_installed_info_preserves_exact_native_identity(self) -> None:
        self.assertEqual(hashlib.sha256(self.PRODUCT.encode()).hexdigest(),
                         "26bfa84afc88b7eea564031e47bc1fb9a82423608d4c668a1f9cc7c951b6c7cf")
        self.assertEqual(hashlib.sha256(self.NATIVE.encode()).hexdigest(),
                         "e9dd1f4385078aa444e85aeea8bf1bc106c11dd0b00fc993f67a2c852fac4e95")
        for value, native in ((self.PRODUCT, False), (self.NATIVE, True)):
            with self.subTest(native=native):
                result = self.normalize(value, native)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(result.stdout, "tree.x86_64\t2.2.1-4.fc44\n")

    def test_installed_product_rejects_wrong_identity_version_and_duplicates(self) -> None:
        for value in (
            self.PRODUCT.replace("tree.x86_64", "tree"),
            self.PRODUCT.replace("tree.x86_64", "tree.i686"),
            self.PRODUCT.replace("tree.x86_64", "tree-x86_64"),
            self.PRODUCT.replace("tree.x86_64", "tree.addon.x86_64"),
            self.PRODUCT.replace("2.2.1-4.fc44", "2.2.2-4.fc44"),
            self.PRODUCT.replace("Version: 2.2.1-4.fc44", "Version: 1:2.2.1-4.fc44"),
            self.PRODUCT + "Name: tree.x86_64\n",
            self.PRODUCT + "Version: 2.2.1-4.fc44\n",
        ):
            with self.subTest(value=value):
                result = self.normalize(value)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertEqual(result.stdout, "")

    def test_native_info_rejects_wrong_fields_and_ambiguous_records(self) -> None:
        for value in (
            self.NATIVE.replace("Architecture: x86_64", "Architecture: i686"),
            self.NATIVE.replace("Architecture: x86_64", "Architecture: "),
            self.NATIVE.replace("Name        : tree", "Name        : tree.addon"),
            self.NATIVE.replace("Version     : 2.2.1", "Version     : 2.2.2"),
            self.NATIVE.replace("Release     : 4.fc44", "Release     : 5.fc44"),
            self.NATIVE + "Architecture: x86_64\n",
            self.NATIVE + "Name: tree\n",
            self.NATIVE + "Version: 2.2.1\n",
            self.NATIVE + "Release: 4.fc44\n",
            self.NATIVE + "Epoch: 1\n",
            self.NATIVE + "Epoch: 0\nEpoch: 0\n",
        ):
            with self.subTest(value=value):
                result = self.normalize(value, True)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertEqual(result.stdout, "")

    def test_available_shape_is_explicit_and_epoch_remains_bound(self) -> None:
        available = self.PRODUCT.replace("tree.x86_64", "tree").replace("Installed: yes", "Installed: no")
        for value, native in ((available, False), (self.NATIVE, True)):
            result = self.normalize(value, native, "available")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout, "tree.x86_64\t2.2.1-4.fc44\n")
        self.assertNotEqual(self.normalize(self.PRODUCT, phase="available").returncode, 0)
        self.assertNotEqual(self.normalize(available, phase="unknown").returncode, 0)
        versioned = self.PRODUCT.replace("2.2.1-4.fc44", "2:2.2.1-4.fc44")
        self.assertEqual(self.normalize(versioned, evr="2:2.2.1-4.fc44").stdout,
                         "tree.x86_64\t2:2.2.1-4.fc44\n")
        self.assertEqual(self.normalize(self.NATIVE + "Epoch: 2\n", True, evr="2:2.2.1-4.fc44").stdout,
                         "tree.x86_64\t2:2.2.1-4.fc44\n")
        self.assertNotEqual(self.normalize(self.NATIVE + "Epoch: 1\n", True, evr="2:2.2.1-4.fc44").returncode, 0)

    def test_machine_query_pins_one_installed_or_exact_available_candidate(self) -> None:
        installed = "tree\tx86_64\t0:2.2.1-4.fc44\n"
        self.assertEqual(self.query(installed).stdout, "tree.x86_64\t2.2.1-4.fc44\n")
        self.assertEqual(self.query(installed.replace("0:", "2:")).stdout,
                         "tree.x86_64\t2:2.2.1-4.fc44\n")
        available = installed + "tree\ti686\t0:2.2.1-4.fc44\n" + "tree\tx86_64\t0:2.1-1.fc44\n"
        self.assertEqual(self.query(available, "available", evr="2.2.1-4.fc44").stdout,
                         "tree.x86_64\t2.2.1-4.fc44\n")
        for value, phase, evr in (
            ("", "installed", ""), (installed * 2, "installed", ""),
            (installed + "tree\ti686\t2.2.1-4.fc44\n", "installed", ""),
            (installed.replace("x86_64", "i686"), "installed", ""),
            (installed.replace("tree\t", "tree.addon\t"), "installed", ""),
            (installed.replace("\t0:", "\t00:"), "installed", ""),
            (installed.replace("x86_64", "x86-64"), "installed", ""),
            (installed.replace("4.fc44", "4.fc44 extra"), "installed", ""),
            (installed * 2, "available", "2.2.1-4.fc44"),
            (installed, "available", "1:2.2.1-4.fc44"),
            (installed.replace("x86_64", "i686"), "available", "2.2.1-4.fc44"),
        ):
            with self.subTest(value=value, phase=phase, evr=evr):
                result = self.query(value, phase, evr=evr)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertEqual(result.stdout, "")

    def test_native_query_failure_preserves_streams_and_exact_exit(self) -> None:
        tools = self.directory / "tools"
        tools.mkdir()
        for name in ("rpm", "dnf"):
            executable = tools / name
            executable.write_text("#!/bin/sh\nprintf 'tree\\tx86_64\\t0:2.2.1-4.fc44\\n'\nprintf 'native-query-refused\\n' >&2\nexit 17\n", encoding="utf-8")
            executable.chmod(0o700)
        definitions = self.definition("fedora_identity_from_query") + self.definition("capture_fedora_info_identity")
        invocation = 'set -euo pipefail\nEXPORT_DIR=$1\n' + definitions + 'capture_fedora_info_identity installed "" ""\n'
        result = subprocess.run(["/bin/bash", "-s", "--", str(self.directory)], input=invocation,
                                cwd=self.directory, env={**os.environ, "PATH": str(tools) + ":" + os.environ["PATH"]},
                                capture_output=True, text=True, check=False, timeout=10)
        self.assertEqual(result.returncode, 17, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual((self.directory / "native-identity-query.stdout").read_text(), "tree\tx86_64\t0:2.2.1-4.fc44\n")
        self.assertEqual((self.directory / "native-identity-query.stderr").read_text(), "native-query-refused\n")

    def test_product_phase_requires_single_installed_flag(self) -> None:
        for value, phase in (
            (self.PRODUCT.replace("Installed: yes", "Installed: no"), "installed"),
            (self.PRODUCT.replace("Installed: yes", "Installed: unknown"), "installed"),
            (self.PRODUCT.replace("   Installed: yes\n", ""), "installed"),
            (self.PRODUCT + "Installed: yes\n", "installed"),
            (self.PRODUCT.replace("tree.x86_64", "tree"), "available"),
        ):
            with self.subTest(value=value, phase=phase):
                result = self.normalize(value, phase=phase)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertEqual(result.stdout, "")

    def test_available_capture_is_cache_only_and_records_exact_native_arguments(self) -> None:
        tools = self.directory / "tools"
        tools.mkdir()
        rpm = tools / "rpm"
        rpm.write_text("#!/bin/sh\nprintf 'x86_64\\n'\n", encoding="utf-8")
        dnf = tools / "dnf"
        dnf.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$QUERY_ARGUMENTS\"\nprintf 'tree\\tx86_64\\t2:2.2.1-4.fc44\\ntree\\ti686\\t2:2.2.1-4.fc44\\ntree\\tx86_64\\t2.1-1.fc44\\n'\n", encoding="utf-8")
        rpm.chmod(0o700)
        dnf.chmod(0o700)
        definitions = self.definition("fedora_identity_from_query") + self.definition("capture_fedora_info_identity")
        invocation = 'set -euo pipefail\nEXPORT_DIR=$1\n' + definitions + 'capture_fedora_info_identity available -before "2:2.2.1-4.fc44"\n'
        arguments = self.directory / "query-arguments.txt"
        result = subprocess.run(["/bin/bash", "-s", "--", str(self.directory)], input=invocation,
                                cwd=self.directory, env={**os.environ, "PATH": str(tools) + ":" + os.environ["PATH"], "QUERY_ARGUMENTS": str(arguments)},
                                capture_output=True, text=True, check=False, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "tree.x86_64\t2:2.2.1-4.fc44\n")
        self.assertEqual(arguments.read_text().splitlines(),
                         ["--cacheonly", "repoquery", "--available", "--latest-limit=1", "--arch=x86_64", "--queryformat", "%{name}\t%{arch}\t%{evr}\\n", "tree"])
        self.assertEqual((self.directory / "native-architecture.stdout").read_text(), "x86_64\n")
        self.assertTrue((self.directory / "native-identity-query-before.stdout").read_text().startswith("tree\tx86_64\t2:"))
        self.assertEqual((self.directory / "native-identity-query-before.stderr").read_text(), "")

    def test_machine_query_refuses_oversized_available_stream(self) -> None:
        value = "tree\tx86_64\t2.2.1-4.fc44\n" + "tree\ti686\t2.2.1-4.fc44\n" * 4000
        self.assertGreater(len(value.encode()), 65536)
        result = self.query(value, "available", evr="2.2.1-4.fc44")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout, "")

    def test_non_fedora_name_version_contract_stays_bare_and_exact(self) -> None:
        path = self.directory / "non-fedora.txt"
        path.write_text("Name: tree\nVersion: 2.2.1-4\n", encoding="utf-8")
        invocation = 'set -euo pipefail\ndistro=arch\n' + self.definition("normalize_info") + 'normalize_info false "$1" installed "" "2.2.1-4"\n'
        result = subprocess.run(["/bin/bash", "-s", "--", str(path)], input=invocation,
                                capture_output=True, text=True, check=False, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "tree\t2.2.1-4\n")

class TrixieBenchmarkIdentityTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parents[1]
        self.directory = tempfile.TemporaryDirectory(prefix="trixie-benchmark-identity-")
        self.addCleanup(self.directory.cleanup)
        self.output = Path(self.directory.name)
        self.guest = (self.root / "benchmark-hyperfine.sh").read_text()
        self.host = (self.root / "scripts/benchmark-qemu.sh").read_text()

    def bash(self, body):
        result = subprocess.run(
            ["bash", "-euo", "pipefail"], input=body, text=True,
            capture_output=True, timeout=10, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def identity_setup(self, os_id="debian", version="13"):
        release = self.output / "os-release"
        release.write_text(f'ID={os_id}\nVERSION_ID="{version}"\n')
        fragment = self.guest.split('    distro=$(awk', 1)[1].split('    extra_native=()', 1)[0]
        return 'distro=$(awk' + fragment.replace('/etc/os-release', shlex.quote(str(release)))

    def test_guest_identity_distinguishes_debian_13_from_other_backends(self):
        for os_id, version, expected in (
            ("debian", "13", "debian-trixie"), ("debian", "12", "debian"),
            ("ubuntu", "24.04", "ubuntu"), ("fedora", "44", "fedora"),
            ("arch", "", "arch"),
        ):
            with self.subTest(os_id=os_id, version=version):
                result = self.bash(self.identity_setup(os_id, version) +
                    'printf "%s\\n%s\\n" "$distro" "$evidence_distro"\n')
                self.assertEqual(result.splitlines(), [os_id, expected])

    def receipt(self, transaction):
        for name in ("command", "info.commands", "search.commands", "explicit.commands"):
            (self.output / f"{name}.json").write_text('[]')
        (self.output / "boot-id.txt").write_text('fixture-boot\n')
        start = 'jq -n --arg distro "$distro" --arg ' + (
            'operation "$GUEST_TRANSACTION"' if transaction else 'json search_equivalent'
        )
        if not transaction:
            start = 'jq -n --arg distro "$distro" --argjson search_equivalent'
        # Both old and repaired fragments are executable with the same fixtures.
        if start not in self.guest:
            start = start.replace('"$distro"', '"$evidence_distro"')
        fragment = start + self.guest.split(start, 1)[1].split('> "$EXPORT_DIR/summary.json"', 1)[0]
        setup = f'EXPORT_DIR={shlex.quote(str(self.output))}\n'
        setup += 'GUEST_TRANSACTION=install\nGUEST_TOOL=omg\nexpected_version=2\n'
        setup += 'search_equivalent=false\nWARMUP=3\nMIN_RUNS=20\nMAX_RUNS=50\n'
        return json.loads(self.bash(self.identity_setup() + setup + fragment))

    def test_read_receipt_preserves_trixie_identity(self):
        self.assertEqual(self.receipt(False)["distro"], "debian-trixie")

    def test_transaction_receipt_preserves_trixie_identity(self):
        self.assertEqual(self.receipt(True)["distro"], "debian-trixie")

    def test_host_selects_apt_labels_for_trixie(self):
        gate = self.host.split('if [[ "$benchmark" == true && "$rc" == 0 ]]; then', 1)[1]
        fragment = gate.split('  case "$distro" in', 1)[1].split('  esac', 1)[0]
        labels = json.loads(self.bash('distro=debian-trixie\ncase "$distro" in' +
            fragment + 'esac\nprintf "%s" "$expected_commands"\n'))
        self.assertEqual(labels, {
            "info": ["OMG", "apt-cache", "apt"],
            "search": ["OMG", "apt-cache", "apt"],
            "explicit": ["OMG", "apt-mark"],
        })


class HyperfineExportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="hyperfine-export-")
        self.addCleanup(self.directory.cleanup)
        self.output = Path(self.directory.name)
        root = Path(__file__).resolve().parents[1]
        script = (root / "benchmark-hyperfine.sh").read_text()
        self.definition = "run_hyperfine() {" + script.split("run_hyperfine() {", 1)[1].split("\ncommand_json()", 1)[0]
        self.recorder = load_recorder()

    def fixture(self, count: int = 2) -> dict:
        summary = {
            "unit": "second", "count": count, "mean": 0.2,
            "median": 0.2, "min": 0.2, "max": 0.2,
            "stddev": 0.0 if count > 1 else None,
        }
        return {
            "schema_version": 2, "primary_metric": "time_wall_clock",
            "results": [{
                "name": "OMG", "command": "/tmp/omg info tree",
                "measurements": [{
                    "time_wall_clock": {"value": 0.2, "unit": "second"},
                    "time_user": {"value": 0.01, "unit": "second"},
                    "time_system": {"value": 0.02, "unit": "second"},
                    "exit_code": 0,
                } for _ in range(count)],
                "summary": {
                    "time_wall_clock": summary,
                    "time_user": {**summary, "mean": 0.01},
                    "time_system": {**summary, "mean": 0.02},
                },
            }],
        }

    def export(self, payload: dict, producer_exit: int = 0) -> subprocess.CompletedProcess[str]:
        fixture = self.output / "input.json"
        fixture.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        producer = '''
hyperfine() {
    while [[ $# -gt 0 ]]; do
        if [[ $1 == --export-json ]]; then cp -- "$FIXTURE" "$2"; break; fi
        shift
    done
    return "$PRODUCER_EXIT"
}
'''
        invocation = "set -euo pipefail\nWARMUP=3\nMIN_RUNS=20\nMAX_RUNS=50\n" + producer + self.definition
        # Exercise conditional callers too: errexit is disabled inside a function
        # invoked in an OR-list, so producer and conversion errors need propagation.
        invocation += '\nrc=0\nrun_hyperfine search.json search.md --command-name OMG "omg info tree" || rc=$?\nexit "$rc"\n'
        return subprocess.run(
            ["/bin/bash", "-s"], input=invocation, cwd=self.output,
            env={**os.environ, "FIXTURE": str(fixture), "PRODUCER_EXIT": str(producer_exit)},
            text=True, capture_output=True, timeout=10, check=False,
        )

    def test_legacy_export_is_byte_identical(self) -> None:
        result = self.export({"results": [measurement("OMG", 0.2)]})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.output / "search.json").read_bytes(), (self.output / "input.json").read_bytes())
        self.assertFalse((self.output / "search.raw.json").exists())
        self.assertEqual(self.recorder.validate_results(self.output), [])

    def test_v2_preserves_raw_export_labels_samples_and_statistics(self) -> None:
        result = self.export(self.fixture())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.output / "search.raw.json").read_bytes(), (self.output / "input.json").read_bytes())
        payload = json.loads((self.output / "search.json").read_text())
        self.assertEqual(payload["source_schema_version"], 2)
        self.assertEqual(payload["results"], [measurement("OMG", 0.2) | {"user": 0.01, "system": 0.02}])
        self.assertEqual(self.recorder.validate_results(self.output), [])
        self.assertEqual(self.recorder.summarize_scenario(payload)[0]["mean_ms"], 200.0)

    def test_v2_single_sample_keeps_unknown_deviation(self) -> None:
        result = self.export(self.fixture(count=1))
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads((self.output / "search.json").read_text())
        self.assertIsNone(payload["results"][0]["stddev"])
        self.assertIsNone(self.recorder.summarize_scenario(payload)[0]["stddev_ms"])

    def test_failed_samples_remain_failed(self) -> None:
        payload = self.fixture()
        payload["results"][0]["measurements"][1]["exit_code"] = 17
        result = self.export(payload)
        self.assertEqual(result.returncode, 0, result.stderr)
        converted = json.loads((self.output / "search.json").read_text())
        self.assertEqual(converted["results"][0]["exit_codes"], [0, 17])
        self.assertTrue(any("non-zero exit" in error for error in self.recorder.validate_results(self.output)))

    def test_fabricated_summary_remains_rejected(self) -> None:
        payload = self.fixture()
        payload["results"][0]["summary"]["time_wall_clock"]["mean"] = 0.001
        result = self.export(payload)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(any("mean does not match" in error for error in self.recorder.validate_results(self.output)))

    def test_unsupported_or_incomplete_exports_fail(self) -> None:
        cases = [self.fixture() for _ in range(7)]
        cases[0]["schema_version"] = 3
        cases[1]["primary_metric"] = "time_user"
        cases[2]["results"][0]["summary"]["time_wall_clock"]["unit"] = "millisecond"
        cases[3]["results"][0]["summary"]["time_user"]["count"] = 1
        cases[4]["results"][0]["measurements"][0]["time_wall_clock"]["unit"] = "millisecond"
        cases[5]["results"][0]["name"] = ""
        cases[6]["results"][0]["measurements"] = []
        for payload in cases:
            with self.subTest(payload=payload):
                result = self.export(payload)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual((self.output / "search.json").read_bytes(), (self.output / "input.json").read_bytes())
                self.assertFalse((self.output / "search.raw.json").exists())

    def test_producer_failure_retains_exact_exit_and_raw_file(self) -> None:
        result = self.export(self.fixture(), producer_exit=77)
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertEqual((self.output / "search.json").read_bytes(), (self.output / "input.json").read_bytes())
        self.assertFalse((self.output / "search.raw.json").exists())


if __name__ == "__main__":
    unittest.main()
