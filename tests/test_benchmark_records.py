"""Regression checks for unbiased Hyperfine evidence admission."""

from __future__ import annotations

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
        for name in ("dirname", "mkdir"):
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
        ):
            executable = shutil.which(name)
            if executable is None:
                raise RuntimeError(f"Missing fixture prerequisite: {name}")
            (tools / name).symlink_to(executable)
        stubs = {
            "omg": '#!/bin/bash\ncase "$1" in ec) echo 1;; *) echo firefox;; esac\n',
            "omgd": "#!/bin/bash\nexec /usr/bin/sleep 60\n",
            "hyperfine": "#!/bin/bash\nexit 0\n",
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
                     if line.startswith("timeout 15 ssh ") and "os-release" in line)
        self.assertLess(self.text.index(gate), self.text.index(probe))
        remote = shlex.split(probe)[-1]
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


if __name__ == "__main__":
    unittest.main()
