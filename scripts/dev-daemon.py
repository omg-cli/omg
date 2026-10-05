#!/usr/bin/env python3
"""Build and launch the daemon at Cargo's reported executable path."""

import json
import os
from pathlib import Path
import subprocess
import sys
import time


def main():
    # Cargo supplies the actual path, including target-dir/config/target overrides.
    result = subprocess.run(
        ["cargo", "build", "--features", "arch", "--message-format=json-render-diagnostics"],
        stdout=subprocess.PIPE, text=True, check=False,
    )
    if result.returncode:
        print("Cargo build failed; daemon was not launched.", file=sys.stderr)
        return result.returncode

    executable = None
    for line in result.stdout.splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            # Cargo documents that stdout can also contain non-JSON output.
            print(line)
            continue
        if not isinstance(message, dict):
            continue
        target = message.get("target", {})
        if (message.get("reason") == "compiler-artifact"
                and target.get("name") == "omgd"
                and "bin" in target.get("kind", [])
                and message.get("executable")):
            executable = Path(message["executable"]).resolve()

    if executable is None:
        print("Cargo did not report an omgd executable; daemon was not launched.", file=sys.stderr)
        return 1
    if not executable.is_file() or not os.access(executable, os.X_OK):
        print(f"Daemon executable is missing or not executable: {executable}", file=sys.stderr)
        return 1

    print(f"Starting OMG daemon: {executable}", flush=True)
    # Preserve the existing dev recipe's restart behavior.
    subprocess.run(["pkill", "omgd"], stderr=subprocess.DEVNULL, check=False)
    try:
        daemon = subprocess.Popen([str(executable)])
    except OSError as error:
        print(f"Cannot launch daemon {executable}: {error}", file=sys.stderr)
        return 1
    time.sleep(1)
    status = daemon.poll()
    if status is not None:
        print(f"Daemon exited during startup (status {status}): {executable}", file=sys.stderr)
        return 1
    print(f"Daemon process started (PID {daemon.pid}); readiness not checked. "
          "Run 'make dev-stop' to stop.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except OSError as error:
        print(f"Cannot start development daemon: {error}", file=sys.stderr)
        sys.exit(1)
