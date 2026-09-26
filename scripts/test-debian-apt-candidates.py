"""Compare OMG with APT across isolated stable, security, and backports pockets."""

import argparse
import email.utils
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--omg-binary", type=pathlib.Path, required=True)
parser.add_argument("--scenario", choices=("security", "backports", "both"), default="both")
args = parser.parse_args()
binary = str(args.omg_binary.resolve(strict=True))


def run(command, environment):
    result = subprocess.run(
        command, env=environment, text=True, capture_output=True, timeout=45, check=False
    )
    if result.returncode:
        raise AssertionError(
            f"{command!r} exited {result.returncode}\n{result.stdout}\n{result.stderr}"
        )
    return result.stdout


def require(condition, evidence):
    if not condition:
        raise AssertionError(evidence)


def verify_candidate(environment, version, description):
    policy = run(["apt-cache", "policy", "omg-pin-probe"], environment)
    candidate = next(
        (line.strip().removeprefix("Candidate: ") for line in policy.splitlines()
         if line.strip().startswith("Candidate: ")),
        None,
    )
    require(candidate == version, f"native APT candidate changed: {policy}")

    info = json.loads(run([binary, "info", "omg-pin-probe", "--json"], environment))
    require(info["version"] == version and info["description"] == description, info)
    search = json.loads(
        run([binary, "search", "omg-pin-probe", "--json", "--no-aur", "--limit", "1"], environment)
    )
    require(len(search) == 1 and search[0]["name"] == "omg-pin-probe", search)
    require(search[0]["version"] == version and search[0]["description"] == description, search)

    native_plan = run(["apt-get", "-s", "install", "--", "omg-pin-probe"], environment)
    preview = run([binary, "install", "--dry-run", "omg-pin-probe"], environment)
    require(native_plan.strip() in preview, f"preview differs from APT\n{native_plan}\n{preview}")
    require(f"Inst omg-pin-probe ({version} " in native_plan, native_plan)
    require("No changes will be made (dry run)" in preview, preview)


with tempfile.TemporaryDirectory(prefix="omg-apt-pin-") as temporary:
    root = pathlib.Path(temporary)
    repository = root / "repo"
    architecture = subprocess.check_output(["dpkg", "--print-architecture"], text=True).strip()
    for suite, version, extra in (
        ("stable", "1.0-1", ""),
        ("security", "1.1-1", ""),
        ("backports", "2.0-1~bpo", "NotAutomatic: yes\nButAutomaticUpgrades: yes\n"),
    ):
        distribution = repository / "dists" / suite
        package_dir = distribution / "main" / f"binary-{architecture}"
        package_dir.mkdir(parents=True)
        content = (
            "Package: omg-pin-probe\n"
            f"Version: {version}\n"
            f"Architecture: {architecture}\n"
            "Section: utils\nPriority: optional\nInstalled-Size: 10\n"
            "Maintainer: OMG test <test@example.invalid>\n"
            f"Description: isolated {suite} candidate\n"
            "Filename: pool/main/o/omg-pin-probe.deb\n"
            "Size: 100\nSHA256: " + "0" * 64 + "\n\n"
        ).encode()
        (package_dir / "Packages").write_bytes(content)
        digest = hashlib.sha256(content).hexdigest()
        relative = f"main/binary-{architecture}/Packages"
        (distribution / "Release").write_text(
            f"Origin: OMG Fixture\nLabel: OMG Fixture\nSuite: {suite}\n"
            f"Codename: {suite}\nArchitectures: {architecture}\nComponents: main\n"
            f"Date: {email.utils.formatdate(usegmt=True)}\n"
            f"{extra}SHA256:\n {digest} {len(content)} {relative}\n"
        )
    (root / "sources.list").write_text(
        f"deb [trusted=yes] file://{repository} stable main\n"
        f"deb [trusted=yes] file://{repository} security main\n"
        f"deb [trusted=yes] file://{repository} backports main\n"
    )
    (root / "status").write_text("")
    for directory in ("sourceparts", "preferences.d", "lists/partial", "archives/partial"):
        (root / directory).mkdir(parents=True)
    (root / "preferences").write_text("")
    (root / "apt.conf").write_text(
        f'Dir::Etc::main "{root / "empty.conf"}";\n'
        f'Dir::Etc::parts "{root / "sourceparts"}";\n'
        f'Dir::Etc::sourcelist "{root / "sources.list"}";\n'
        f'Dir::Etc::sourceparts "{root / "sourceparts"}";\n'
        f'Dir::Etc::preferences "{root / "preferences"}";\n'
        f'Dir::Etc::preferencesparts "{root / "preferences.d"}";\n'
        f'Dir::State::lists "{root / "lists"}";\n'
        f'Dir::State::status "{root / "status"}";\n'
        f'Dir::Cache::archives "{root / "archives"}";\n'
    )
    (root / "empty.conf").write_text("")
    environment = dict(os.environ, APT_CONFIG=str(root / "apt.conf"), OMG_DISABLE_DAEMON="1")
    environment.pop("OMG_TEST_MODE", None)
    environment.pop("OMG_TEST_DISTRO", None)
    run(["apt-get", "update"], environment)
    verify_candidate(environment, "1.1-1", "isolated security candidate")
    (root / "preferences").write_text(
        "Package: omg-pin-probe\nPin: version 2.0-1~bpo\nPin-Priority: 1001\n"
    )
    if args.scenario in ("backports", "both"):
        verify_candidate(environment, "2.0-1~bpo", "isolated backports candidate")
    print(f"PASS: native APT {args.scenario} candidate, pocket metadata, and preview parity")
