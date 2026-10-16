#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

EXPECTED_NODE = "3f275b7a2f423797958ac62f0f39a1bdd8e79da53cb9c5e0ea783542dcb36e8c"
SELECTORS = [
    "runtimes::node::tests::node_linux_cleanup_live_overflow_injected_group_eperm",
    "runtimes::node::tests::node_linux_cleanup_already_terminal_skips_direct_signal",
    "runtimes::node::tests::node_linux_cleanup_racing_exit_esrch_retains_overflow",
    "runtimes::node::tests::node_linux_cleanup_racing_exit_eio_retains_group_failure",
    "runtimes::node::tests::node_linux_cleanup_valid_output_retains_group_failure",
]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], timeout=15).decode().strip()


def command(repo, out, label, seconds, argv):
    complete = ["timeout", "-k", "5s", f"{seconds}s", *map(str, argv)]
    with (out / f"{label}.stdout").open("xb") as stdout, (out / f"{label}.stderr").open("xb") as stderr:
        result = subprocess.run(complete, cwd=repo, stdout=stdout, stderr=stderr, check=False)
    return {"argv": complete, "exit": result.returncode,
            "stdout_sha256": sha(out / f"{label}.stdout"),
            "stderr_sha256": sha(out / f"{label}.stderr")}


def main():
    repo = Path.cwd().resolve()
    out = Path(os.environ["PR940_RED_OUT"]).resolve()
    out.mkdir(parents=True, exist_ok=False)
    receipt = {"state": "NOT_PROVEN", "commands": {}, "selectors": SELECTORS,
               "claim_scope": "Five ordinary Node Linux unit regressions. Direct child PID assertions only."}
    source = repo / "src/runtimes/node.rs"
    binary = None
    try:
        expected_commit = os.environ.get("GITHUB_SHA", "")
        if not re.fullmatch(r"[0-9a-f]{40}", expected_commit):
            raise ValueError("Missing exact GitHub event commit")
        receipt["head"] = git(repo, "rev-parse", "HEAD")
        receipt["tree"] = git(repo, "rev-parse", "HEAD^{tree}")
        if receipt["head"] != expected_commit or not re.fullmatch(r"[0-9a-f]{40}", receipt["tree"]):
            raise ValueError("Checkout differs from exact GitHub event commit")
        receipt["identity_scope"] = "External root admission must bind this head/tree and source/script hashes to authenticated run/artifact metadata."
        pins = ["src/runtimes/node.rs", "src/lib.rs", "Cargo.toml", "Cargo.lock",
                ".github/workflows/ci.yml", "scripts/pr940-node-linux-red-proof.py"]
        receipt["source_before"] = {name: sha(repo / name) for name in pins}
        for name in pins:
            committed = subprocess.check_output(["git", "-C", str(repo), "show", f"HEAD:{name}"], timeout=15)
            if hashlib.sha256(committed).hexdigest() != receipt["source_before"][name]:
                raise ValueError(f"Working source differs from bound commit: {name}")
        if sha(source) != EXPECTED_NODE:
            raise ValueError("Node source differs from frozen old-production test variant")
        build = command(repo, out, "cargo-build", 480,
                        ["cargo", "test", "--lib", "--no-default-features", "--features", "debian,pgp,license",
                         "--locked", "--profile", "test", "--no-run", "--message-format=json-render-diagnostics"])
        receipt["commands"]["build"] = build
        if build["exit"] != 0:
            raise ValueError("Build/setup/timeout failure is not behavioral RED")
        artifacts = []
        for line in (out / "cargo-build.stdout").read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            if (row.get("reason") == "compiler-artifact" and row.get("target", {}).get("name") == "omg_lib"
                    and row.get("target", {}).get("kind") == ["lib"] and row.get("profile", {}).get("test") is True
                    and row.get("executable")):
                artifacts.append(row)
        if len(artifacts) != 1 or artifacts[0].get("fresh") is not False:
            raise ValueError("Expected exactly one freshly built owning library test executable")
        artifact = artifacts[0]
        if Path(artifact["target"]["src_path"]).resolve(strict=True) != repo / "src/lib.rs":
            raise ValueError("Compiler artifact is not the exact owning library source")
        features = set(artifact.get("features", []))
        if not {"debian", "pgp", "license"} <= features or features & {"arch", "fedora", "macos", "debian-pure"}:
            raise ValueError("Compiler artifact feature graph differs from the selected proof")
        binary = Path(artifact["executable"]).resolve(strict=True)
        target = Path(os.environ.get("CARGO_TARGET_DIR", repo / "target")).resolve()
        if not binary.is_relative_to(target) or not binary.is_file():
            raise ValueError("Owning executable is outside the build target")
        receipt["cargo_artifact"] = artifact
        receipt["binary"] = str(binary)
        receipt["binary_before"] = sha(binary)
        receipt["node_before_list"] = sha(source)
        if receipt["node_before_list"] != EXPECTED_NODE:
            raise ValueError("Node source changed during build")
        listing = command(repo, out, "selected-list", 30,
                          [binary, "node_linux_cleanup_", "--list", "--format", "terse", "--color", "never"])
        receipt["commands"]["list"] = listing
        if listing["exit"] != 0:
            raise ValueError("Compiler listing failed or timed out")
        lines = (out / "selected-list.stdout").read_text(encoding="utf-8").splitlines()
        listed = [line[:-6] for line in lines if line.endswith(": test")]
        if sorted(listed) != sorted(SELECTORS) or len(listed) != 5:
            raise ValueError("Exact selected owning-library test list mismatch")
        run = command(repo, out, "selected-red", 120,
                      [binary, "node_linux_cleanup_", "--test-threads=1", "--color", "never"])
        receipt["commands"]["selected"] = run
        if run["exit"] != 101:
            raise ValueError("Expected ordinary libtest assertion-failure exit 101")
        stdout = (out / "selected-red.stdout").read_text(encoding="utf-8")
        stderr = (out / "selected-red.stderr").read_text(encoding="utf-8")
        text = stdout + "\n" + stderr
        if ("HARNESS" in text or "timed out" in text or stderr.strip()
                or "test result: FAILED. 0 passed; 5 failed; 0 ignored;" not in stdout):
            raise ValueError("Harness/setup/partial selected run is not proof")
        failed = re.findall(r"^test (runtimes::node::tests::\w+) \.\.\. FAILED$", stdout, re.M)
        if sorted(failed) != sorted(SELECTORS):
            raise ValueError("Exact five named ordinary failures were not observed")
        sections = dict(re.findall(r"^---- ([\w:]+) stdout ----\n(.*?)(?=^---- |^failures:|\Z)", stdout, re.M | re.S))
        if set(sections) != set(SELECTORS):
            raise ValueError("Missing exact per-test assertion output")
        for name in SELECTORS[:4]:
            if ("capture refusal was lost:" not in sections[name] or "panicked at" not in sections[name]
                    or "Failed to terminate Node.js probe process group" not in sections[name]):
                raise ValueError(f"Wrong behavioral failure for {name}")
        last = sections[SELECTORS[4]]
        if not ("panicked at" in last and "assertion `left == right` failed" in last
                and re.search(r"\bleft: 1\s+right: 0", last)):
            raise ValueError("Valid-output test did not fail for direct-leader count 1 versus 0")
        receipt["state"] = "EXPECTED_FIVE_NAMED_ORDINARY_ASSERTION_FAILURES"
        receipt["interpretation"] = "Selected RED only. Unrelated full CI failures are not this proof."
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError) as error:
        receipt["rejection"] = f"{type(error).__name__}: {error}"
    finally:
        receipt["node_after"] = sha(source)
        if "source_before" in receipt:
            receipt["source_after"] = {name: sha(repo / name) for name in receipt["source_before"]}
            if receipt["source_after"] != receipt["source_before"]:
                receipt["state"] = "NOT_PROVEN"
                receipt["rejection"] = "Bound source changed during proof"
        if binary is not None:
            receipt["binary_after"] = sha(binary)
            if receipt["binary_after"] != receipt.get("binary_before"):
                receipt["state"] = "NOT_PROVEN"
                receipt["rejection"] = "Owning executable changed during proof"
        with (out / "receipt.json").open("x", encoding="utf-8") as stream:
            json.dump(receipt, stream, indent=2)
            stream.write("\n")
    print(receipt["state"])
    return 0 if receipt["state"] == "EXPECTED_FIVE_NAMED_ORDINARY_ASSERTION_FAILURES" else 1


if __name__ == "__main__":
    raise SystemExit(main())
