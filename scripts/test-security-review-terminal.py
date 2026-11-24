#!/usr/bin/env python3
"""Check the shared Linux/macOS review boundary in real controlling terminals."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unit", type=Path, required=True)
    args = parser.parse_args()
    unit = args.unit.resolve(strict=True)
    spec = importlib.util.spec_from_file_location(
        "arch_consent", Path(__file__).with_name("test-arch-advisory-consent.py")
    )
    terminal = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(terminal)
    terminal.NAME = "core::privilege::tests::security_review_requires_exact_foreground_terminal_consent"
    cases = ("accept", "split-accept", "generic-yes", "blank", "wrong-review", "eof", "no-tty",
             "interrupt", "terminate", "hangup", "cancelled")
    for case in cases:
        environment = os.environ | {"OMG_TERMINAL_REVIEW_CASE": "accept" if case == "split-accept" else case}
        if case == "split-accept":
            environment.update(TERM="xterm", OMG_TERMINAL_REVIEW_PROGRESS="1")
        if case == "cancelled":
            # Cancellation precedes prompting, so no terminal response is expected.
            result = subprocess.run(
                [str(unit), "--exact", terminal.NAME, "--nocapture", "--test-threads=1"],
                env=environment, capture_output=True, start_new_session=True, timeout=20,
            )
            code, transcript = result.returncode, result.stdout + result.stderr
        else:
            code, transcript = terminal.terminal_case(
                unit, case, environment,
                expected=(b"fixture-runtime", b"CVE-2021-23337", b"https://www.cve.org/"),
            )
        if case in ("interrupt", "terminate", "hangup"):
            assert code == -{"interrupt": signal.SIGINT, "terminate": signal.SIGTERM,
                             "hangup": signal.SIGHUP}[case], (case, code, transcript)
        else:
            assert code == 0 and b"test result: ok. 1 passed; 0 failed; 0 ignored;" in transcript, (case, code, transcript)
        if case == "split-accept":
            label = b"fixture transaction progress"
            before, prompt, after = transcript.partition(b"(default: cancel): ")
            # macOS may echo VEOF and backspaces between the split writes.
            waiting, answer, _ = after.partition(b"ceed")
            assert prompt and answer and label in before, (case, transcript)
            assert label not in waiting, ("progress redrew over the security prompt", transcript)
    print(json.dumps({"passed": len(cases)}))


if __name__ == "__main__":
    main()
