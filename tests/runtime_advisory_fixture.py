"""Owned advisory evidence for synthetic runtime fixtures, never downloads."""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import stat


VENDORS = {
    "node": "nodejs", "python": "cpython", "go": "golang",
    "rust": "rust-lang", "ruby": "ruby-lang", "java": "temurin",
    "bun": "oven-sh", "pi": "earendil-works", "deno": "denoland",
    "zig": "ziglang", "dotnet": "microsoft", "erlang": "erlang",
    "php": "php", "swift": "swiftlang",
}
SOURCE = "https://github.com/omg-cli/omg"
ENDPOINT = "https://omg-advisories.latham.workers.dev/v1/runtimes/"
DEFAULT_POLICY_TOML = (
    'minimum_grade = "Community"\nallow_aur = true\nrequire_pgp = false\n'
    'allowed_licenses = []\nbanned_packages = []\n'
    'advisory_requirement = "optional"\narch_advisory_repositories = []\n'
)


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def default_policy():
    # SecurityPolicy's struct serialization order is part of its binding.
    return {
        "minimum_grade": "Community", "allow_aur": True, "require_pgp": False,
        "allowed_licenses": [], "banned_packages": [],
        "advisory_requirement": "optional", "arch_advisory_repositories": [],
    }


def fixture_cli_environment(root):
    root = Path(root).resolve()
    config = root / "config" / "omg"
    config.mkdir(parents=True, mode=0o700, exist_ok=True)
    (config / "policy.toml").write_text(DEFAULT_POLICY_TOML)
    environment = dict(os.environ)
    for name in ("SUDO_USER", "SUDO_UID", "SUDO_GID", "SUDO_HOME", "DOAS_USER"):
        environment.pop(name, None)
    environment.update(HOME=str(root), XDG_CONFIG_HOME=str(config.parent),
                       OMG_CONFIG_DIR=str(config), OMG_NATIVE_TEST_DATA_DIR="1",
                       OMG_DATA_DIR=str(root / "data"))
    return environment


def tree_digest(root):
    root = Path(root).resolve(strict=True)
    rows = {}
    pending = [root]
    total = 0
    while pending:
        for path in pending.pop().iterdir():
            relative = path.relative_to(root).as_posix()
            if relative in (".omg-install-complete", ".omg-installing"):
                continue
            if len(rows) >= 4096:
                raise ValueError("synthetic runtime fixture exceeds its entry budget")
            metadata = path.lstat()
            mode = metadata.st_mode & 0o777
            if stat.S_ISDIR(metadata.st_mode):
                rows[relative] = ["directory", mode, "", 0]
                pending.append(path)
            elif stat.S_ISREG(metadata.st_mode):
                if metadata.st_size > 64 * 1024 * 1024:
                    raise ValueError("synthetic runtime file exceeds its byte budget")
                payload = path.read_bytes()
                if len(payload) != metadata.st_size:
                    raise ValueError("synthetic runtime changed while hashing")
                total += len(payload)
                if total > 64 * 1024 * 1024:
                    raise ValueError("synthetic runtime fixture exceeds its byte budget")
                if relative == ".omg-npm-advisory-review.json":
                    receipt = json.loads(payload)
                    checked = datetime.fromisoformat(receipt.pop("reviewed_at").replace("Z", "+00:00"))
                    age = (datetime.now(timezone.utc) - checked).total_seconds()
                    if not 0 <= age <= 1800:
                        raise ValueError("synthetic npm review is stale or future dated")
                    payload = json.dumps(receipt, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
                rows[relative] = ["file", mode, sha256(payload), len(payload)]
            elif stat.S_ISLNK(metadata.st_mode):
                if not path.resolve(strict=True).is_relative_to(root):
                    raise ValueError("synthetic runtime link escapes its owner")
                rows[relative] = ["symlink", mode, os.readlink(path), 0]
            else:
                raise ValueError("synthetic runtime contains a special file")
    # Rust PathBuf ordering compares path components, not slash characters.
    ordered = {key: rows[key] for key in sorted(rows, key=lambda item: Path(item).parts)}
    return sha256(encoded(ordered))


def seed_runtime_advisory_fixture(version_root, runtime, requested, config_dir,
                                  *, accept_unknown=False):
    """Seed prior controlled evidence for an already authored synthetic tree.

    Callers must never use this for a downloaded runtime. Unknown product
    mappings require explicit fixture acceptance and remain classified Unknown.
    """
    root = Path(version_root).resolve(strict=True)
    if root.name != requested or root.parent.name != runtime or root.parent.parent.name != "versions":
        raise ValueError("fixture must name its exact owned runtime version directory")
    if root.stat().st_uid != os.geteuid() or stat.S_IMODE(root.stat().st_mode) & 0o022:
        raise ValueError("synthetic runtime owner must be protected and current")
    expected_policy = default_policy()
    # This helper owns only the explicit default policy it writes above.
    policy = Path(config_dir) / "policy.toml"
    if policy.read_text() != DEFAULT_POLICY_TOML:
        raise ValueError("synthetic fixture policy must match its actual private config")
    vendor = VENDORS.get(runtime, "unmapped")
    assessed = vendor != "unmapped"
    if not assessed and not accept_unknown:
        raise ValueError("unmapped synthetic product requires explicit Unknown fixture acceptance")
    exact = requested.removeprefix("v").split("-")[0]
    if runtime == "rust" and not exact[0].isdigit():
        exact = "1.78.0"
    while len(exact.split(".")) < 3:
        exact += ".0"
    if not all(part.isdigit() for part in exact.split("+")[0].split(".")):
        raise ValueError("synthetic fixture needs an exact numeric version")
    os_name = {"Linux": "linux", "Darwin": "macos"}[platform.system()]
    arch = {"x86_64": "x86_64", "AMD64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}[platform.machine()]
    if runtime == "rust":
        for triple, target_os, target_arch in (
            ("x86_64-unknown-linux-gnu", "linux", "x86_64"),
            ("x86_64-unknown-linux-musl", "linux", "x86_64"),
            ("aarch64-unknown-linux-gnu", "linux", "aarch64"),
            ("aarch64-unknown-linux-musl", "linux", "aarch64"),
            ("x86_64-apple-darwin", "macos", "x86_64"),
            ("aarch64-apple-darwin", "macos", "aarch64"),
        ):
            if requested.endswith(triple):
                os_name, arch = target_os, target_arch
                break
        else:
            raise ValueError("synthetic Rust fixture requires a supported explicit host")
    content = tree_digest(root)
    identity = {"schema_version": 1, "runtime": runtime, "requested": requested,
                "version": exact, "vendor": vendor, "build": "controlled integration fixture",
                "source_url": SOURCE, "artifact_sha256": content, "components": {}}
    identity_sha = sha256(encoded(identity))
    policy_sha = sha256(encoded(expected_policy))
    query = {"runtime": runtime, "vendor": vendor, "version": exact, "os": os_name, "arch": arch}
    checked = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    coverage = "assessed" if assessed else "unknown"
    gaps = [] if assessed else [f"No supported runtime advisory product mapping exists for {runtime}"]
    payload_sha = sha256(b"controlled integration fixture")
    source = {"name": "controlled-integration-fixture", "url": SOURCE, "revision": "fixture-v1",
              "payload_sha256": payload_sha, "checked_at": checked, "complete": assessed}
    report = {"schema_version": 1, "identity": query, "checked_at": checked,
              "coverage": coverage, "findings": [], "gaps": gaps, "sources": [source]}
    uid, euid = os.getuid(), os.geteuid()
    acceptance = None
    if not assessed:
        semantic = [coverage, [], gaps, [[source["name"], SOURCE, "fixture-v1", payload_sha, False]]]
        provenance = dict(sorted({"runtime": runtime, "source": ENDPOINT,
                                  "payload_sha256": sha256(encoded(semantic))}.items()))
        origin = {"kind": "runtime_vendor", "runtime": runtime, "vendor": vendor}
        review_record = encoded([[runtime, exact, origin, arch, None, []], "evidence_unavailable", provenance]).decode()
        context = encoded(["omg-runtime-admission-v1", str(root), query, content,
                           identity_sha, policy_sha, uid, euid]).decode()
        acceptance = sha256(encoded(["omg-advisory-risk-with-coverage-v1", context, None, [review_record]]))
    record = {"schema_version": 1, "destination": str(root), "query": query,
              "content_sha256": content, "identity_sha256": identity_sha,
              "policy_sha256": policy_sha, "local_gaps": gaps, "uid": uid, "euid": euid,
              "report": report, "accepted_review": acceptance}
    directory = root.parent / ".security"
    directory.mkdir(mode=0o700, exist_ok=True)
    key = sha256(encoded(str(root)))
    for suffix, value in (("identity", identity), ("admission", record)):
        path = directory / f"{key}.{suffix}.json"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded(value))
