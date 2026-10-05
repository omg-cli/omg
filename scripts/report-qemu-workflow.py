#!/usr/bin/env python3
"""Report QEMU evidence from a trusted workflow_run job without executing it."""
import io
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from qemu_inventory_policy import all_snapshots

MAX_DOWNLOAD = 16 * 1024 * 1024
FAILURES = {"FAIL", "PRODUCT_FAIL", "HARNESS_ERROR", "BLOCKED"}
DISTROS = ("arch", "debian", "ubuntu", "fedora")
GUEST_DISTROS = ("arch", "debian", "debian-trixie", "ubuntu", "fedora")


def required_guest_distros(source):
    """Read a closed guest profile from immutable workflow bytes, never execute it."""
    if not isinstance(source, bytes) or not 0 < len(source) <= 256 * 1024:
        raise ValueError("invalid guest profile source")
    matches = re.findall(r"^ +distros='(\[[^\n]*\])' *$", source.decode('utf-8'), re.M)
    if len(matches) != 1:
        raise ValueError("missing or ambiguous default guest profile")
    values = json.loads(matches[0])
    if not isinstance(values, list) or tuple(values) not in (DISTROS, GUEST_DISTROS):
        raise ValueError("unreviewed default guest profile")
    return tuple(values)


def run_guest_profile(repository, revision):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) or not re.fullmatch('[0-9a-f]{40}', revision):
        raise ValueError("invalid guest profile owner")
    path = '.github/workflows/qemu-matrix.yml'
    value = json.loads(api(f'repos/{repository}/contents/{path}?ref={revision}'), object_pairs_hook=unique_object)
    if (not isinstance(value, dict) or value.get('type') != 'file' or value.get('path') != path
            or value.get('encoding') != 'base64' or type(value.get('size')) is not int
            or not 0 < value['size'] <= 256 * 1024 or not isinstance(value.get('content'), str)):
        raise ValueError("invalid source-bound workflow file")
    content = base64.b64decode(value['content'].replace('\n', ''), validate=True)
    blob = hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest()
    if len(content) != value['size'] or value.get('sha') != blob:
        raise ValueError("guest profile Git blob differs")
    return required_guest_distros(content)


def api(path, limit=1024 * 1024):
    with tempfile.TemporaryFile() as output:
        subprocess.run(["gh", "api", path], stdout=output, check=True, timeout=60)
        if output.tell() > limit:
            raise ValueError("GitHub response exceeds reporting limit")
        output.seek(0)
        return output.read(limit + 1)


def identity(event, live, repository):
    run = event["workflow_run"]
    trusted_workflow = (
        live.get("path") == ".github/workflows/qemu-matrix.yml"
        or (live.get("path") == ".github/workflows/ci.yml"
            and live.get("event") == "push" and live.get("head_branch") == "main")
    )
    if (event["repository"]["full_name"] != repository
            or live["repository"]["full_name"] != repository
            or live["id"] != run["id"] or live["run_attempt"] != run["run_attempt"]
            or live["head_sha"] != run["head_sha"]
            or live["workflow_id"] != run["workflow_id"]
            or not trusted_workflow
            or live.get("head_branch") != "main"
            or live["status"] != "completed"
            or live["event"] not in ("push", "workflow_dispatch", "schedule")
            or not re.fullmatch(r"[0-9a-f]{40}", live["head_sha"])):
        raise ValueError("workflow identity or attempt mismatch")
    return live


def canonical_case_ids(policy):
    inventories = policy.get("inventories") if isinstance(policy, dict) else None
    if not isinstance(inventories, dict) or not inventories:
        raise ValueError("invalid inventory policy")
    identifiers = set()
    for snapshot in inventories.values():
        cases = snapshot.get("cases") if isinstance(snapshot, dict) else None
        if not isinstance(cases, list):
            raise ValueError("invalid inventory policy cases")
        for case in cases:
            case_id = case.get("id") if isinstance(case, dict) else None
            if not isinstance(case_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,120}", case_id):
                raise ValueError("invalid inventory policy case")
            identifiers.update(f"qemu-{distro}-{case_id}" for distro in GUEST_DISTROS)
    identifiers.update(f"qemu-{distro}-lifecycle" for distro in GUEST_DISTROS)
    identifiers.update(f"qemu-{distro}-aarch64-lifecycle" for distro in DISTROS)
    identifiers.update(f"qemu-{distro}-backend-mismatch" for distro in GUEST_DISTROS)
    identifiers.add("qemu-matrix-workflow")
    identifiers.update(("qemu-matrix-x86-workflow", "qemu-matrix-arm-workflow",
                        "qemu-matrix-all-workflow", "qemu-arm-runner-kvm-health"))
    return identifiers


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def diagnostic_excerpt(raw):
    # Redact before truncating: cutting a token's prefix first could prevent
    # the issue helper from recognizing the remaining credential bytes.
    text = raw.decode("utf-8", errors="replace")
    for name in ("GH_TOKEN", "GITHUB_TOKEN"):
        if token := os.environ.get(name):
            text = text.replace(token, "[redacted-token]")
    text = re.sub(r"(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]+", "[redacted-token]", text)
    text = re.sub(r"Bearer [A-Za-z0-9._~+/=-]+", "Bearer [redacted]", text, flags=re.IGNORECASE)
    text = re.sub(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)",
                  "[redacted-private-key]", text, flags=re.DOTALL)
    text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]|\x1b\][^\x07]*\x07", "", text)
    text = text.replace("\r", "\n").replace("```", "[code fence]")
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    text = "\n".join(text.splitlines()[-12:])
    return text.encode("utf-8")[-1300:].decode("utf-8", errors="ignore")


def archive_rows(content, allowed_cases, diagnostics=None, *, guest=None, revision=None):
    if len(content) > MAX_DOWNLOAD:
        raise ValueError("artifact download exceeds limit")
    rows = []
    row_sources = []
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        members = archive.infolist()
        if len(members) > 5000 or sum(member.file_size for member in members) > 256 * 1024 * 1024:
            raise ValueError("artifact expansion exceeds limit")
        seen = set()
        for member in members:
            path = PurePosixPath(member.filename)
            mode = member.external_attr >> 16
            if (path.is_absolute() or ".." in path.parts or "\\" in member.filename
                    or stat.S_ISLNK(mode) or member.filename in seen):
                raise ValueError("unsafe artifact member")
            seen.add(member.filename)
            # Transaction trials use their own `results.json` schema (`id`,
            # `operation`, ...). They are checked by the guest verifier; this
            # reporter only consumes lifecycle and inventory case rows.
            if path.name not in ("results.json", "backend-mismatch-results.json") or path.parent.name == "transactions":
                continue
            if path.name == "backend-mismatch-results.json" and (
                    len(path.parts) != 2 or not re.fullmatch(
                        r"run-[a-zA-Z0-9-]+", path.parent.name)):
                raise ValueError("backend mismatch result is outside its run root")
            if member.file_size > 1024 * 1024:
                raise ValueError("result exceeds limit")
            payload = json.loads(archive.read(member), object_pairs_hook=unique_object)
            if not isinstance(payload, list) or len(payload) > 1000:
                raise ValueError("invalid result collection")
            for row in payload:
                if not isinstance(row, dict):
                    raise ValueError("invalid result row")
                if path.name == "backend-mismatch-results.json" and (
                        row.get("case_id") != f"qemu-{row.get('distro')}-backend-mismatch"
                        or row.get("artifact_source") != "backend-mismatch"):
                    raise ValueError("backend mismatch result has the wrong identity")
                if (not isinstance(row, dict)
                        or not isinstance(row.get("case_id"), str)
                        or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", row["case_id"])
                        or row["case_id"] not in allowed_cases
                        or row.get("distro") not in GUEST_DISTROS
                        or (row.get("distro") == "debian-trixie" and row.get("arch", "x86_64") != "x86_64")
                        or (row["case_id"] != "qemu-matrix-workflow"
                            and not row["case_id"].startswith(f"qemu-{row['distro']}-"))
                        or row.get("result") not in FAILURES | {"PASS", "SKIPPED"}
                        or type(row.get("exit_code")) is not int
                        or not -1 <= row["exit_code"] <= 255
                        or type(row.get("elapsed_seconds")) not in (int, float)
                        or not 0 <= row["elapsed_seconds"] <= 86400):
                    raise ValueError("invalid result row")
                if guest is not None and row["distro"] != guest[0]:
                    raise ValueError("guest result distro differs from artifact identity")
                if guest is not None and "arch" in row and row["arch"] != guest[1]:
                    raise ValueError("guest result architecture differs from artifact identity")
                admitted = {key: row[key] for key in (
                    "case_id", "distro", "result", "exit_code", "elapsed_seconds")}
                if guest is not None:
                    admitted["arch"] = guest[1]
                rows.append(admitted)
                row_sources.append((row, path.parent))
        if guest is not None:
            provenance_members = [member for member in members if member.filename == "provenance.json"]
            if provenance_members:
                if len(provenance_members) != 1 or provenance_members[0].file_size > 4096:
                    raise ValueError("invalid guest provenance")
                provenance = json.loads(archive.read(provenance_members[0]),
                                        object_pairs_hook=unique_object)
                if (not isinstance(provenance, dict)
                        or provenance.get("distro") != guest[0]
                        or provenance.get("arch") != guest[1]
                        or provenance.get("harness_revision") != revision):
                    raise ValueError("guest artifact provenance mismatch")
            else:
                lifecycle = (f"qemu-{guest[0]}-lifecycle" if guest[1] == "x86_64"
                             else f"qemu-{guest[0]}-aarch64-lifecycle")
                if not row_sources or any(
                        row["case_id"] != lifecycle or row["result"] not in FAILURES
                        or not parent.name.startswith("run-setup-")
                        for row, parent in row_sources):
                    raise ValueError("guest artifact lacks provenance outside setup failure")
        # Admission above validates every archive member before any diagnostic
        # is consumed. Read only logs named by a validated failing case; never
        # extract files or execute artifact content. The issue helper applies
        # its existing secret scrubber before publication.
        if diagnostics is not None:
            members_by_name = {member.filename: member for member in members}
            for row, parent in row_sources:
                if row["result"] not in FAILURES or row["case_id"] == "qemu-matrix-workflow":
                    continue
                key = (row["case_id"], row["distro"], guest[1]) if guest else (
                    row["case_id"], row["distro"])
                diagnostics.pop(key, None)
                case = row["case_id"].removeprefix(f"qemu-{row['distro']}-")
                if parent.name == "inventory":
                    candidates = [parent / "rows" / f"{case}{suffix}.log"
                                  for suffix in (".stderr", ".stdout")]
                elif case == "backend-mismatch":
                    candidates = [parent / "backend-mismatch.json",
                                  parent / "backend-mismatch.log"]
                elif case in ("lifecycle", "aarch64-lifecycle"):
                    candidates = [parent / name for name in (
                        "kvm-probe.log", "health-validation.log", "transactions.log",
                        "transaction-validation.log", "guest-check.log", "boot.log",
                        "guest/evidence/index-update.txt",
                        "guest/evidence/daemon-direct.log",
                        "guest/evidence/daemon-advisory-shutdown.log")]
                    doctor_candidates = [parent / f"guest/evidence/doctor-connectivity-{name}"
                                         for name in ("fallback.log", "primary.preflight.log",
                                                      "alternate.preflight.log")]
                    doctor_candidates = [candidate for candidate in doctor_candidates
                                         if (member := members_by_name.get(str(candidate))) is not None
                                         and member.file_size <= 8 * 1024 * 1024
                                         and archive.read(member).strip()]
                    if doctor_candidates:
                        candidates = doctor_candidates + [parent / "guest-check.log"]
                else:
                    candidates = []
                excerpts = []
                if case in ("lifecycle", "aarch64-lifecycle"):
                    receipt = None
                    summary = members_by_name.get(str(parent / "transactions/summary.json"))
                    if summary is not None and summary.file_size <= 1024 * 1024:
                        try:
                            receipt = json.loads(archive.read(summary), object_pairs_hook=unique_object)
                        except (ValueError, UnicodeDecodeError):
                            receipt = None
                        trials = receipt.get("results", []) if isinstance(receipt, dict) else []
                        if isinstance(trials, list):
                            for trial in trials:
                                if (not isinstance(trial, dict)
                                        or not isinstance(trial.get("result"), str)
                                        or trial["result"] not in FAILURES):
                                    continue
                                trial_id = trial.get("id")
                                if not isinstance(trial_id, str) or not re.fullmatch(
                                        r"(?:install|remove)-(?:native|omg)-[0-9]{3}", trial_id):
                                    continue
                                if trial["result"] == "FAIL":
                                    for stream in ("stderr", "stdout"):
                                        name = (f"transactions/trials/{trial_id}/transaction-trial/"
                                                f"transaction.{stream}")
                                        member = members_by_name.get(str(parent / name))
                                        if member is not None and member.file_size <= 8 * 1024 * 1024:
                                            raw = archive.read(member)
                                            if raw.strip():
                                                excerpts.append((name, diagnostic_excerpt(raw)))
                                if trial["result"] == "HARNESS_ERROR":
                                    for boot_name in ("boot.qemu-startup.log", "boot.log"):
                                        name = f"transactions/trials/{trial_id}/{boot_name}"
                                        member = members_by_name.get(str(parent / name))
                                        if member is not None and member.file_size <= 8 * 1024 * 1024:
                                            raw = archive.read(member)
                                            if raw.strip():
                                                excerpts.append((name, diagnostic_excerpt(raw)))
                                                break
                                if not excerpts or trial["result"] == "HARNESS_ERROR":
                                    serial_name = f"transactions/trials/{trial_id}/serial.log"
                                    serial = members_by_name.get(str(parent / serial_name))
                                    if serial is not None and serial.file_size <= 8 * 1024 * 1024:
                                        lines = archive.read(serial).decode("utf-8", errors="replace").splitlines()
                                        signals = [line for line in lines if re.search(
                                            r"fail|error|panic|timed out|lost carrier|gained carrier|DHCP|fe80::",
                                            line, flags=re.IGNORECASE)]
                                        if signals:
                                            priority = [line for line in signals if re.search(
                                                r"fail|error|panic|timed out|lost carrier|fe80::",
                                                line, flags=re.IGNORECASE)]
                                            excerpts.append((serial_name, diagnostic_excerpt(
                                                "\n".join(signals[-4:] + priority[-4:]).encode("utf-8"))))
                                break
                    if not excerpts and isinstance(receipt, dict):
                        preparation_logs = {
                            "automatic-updates": "automatic-updates.log",
                            "prepare-remove": "prepare-remove.log",
                            "remove-repository-state": "remove-repository-state.log",
                            "prepare-remove-health": "prepare-remove-health.log",
                            "stop-prepared-remove": "stop-prepared-remove.log",
                            "prepare-install-boot": "prepare-install-boot.qemu-startup.log",
                            "prepare-install": "prepare-install.log",
                            "install-repository-state": "install-repository-state.log",
                            "prepare-install-health": "prepare-install-health.log",
                            "stop-prepared-install": "stop-prepared-install.log",
                        }
                        phase = receipt.get("phase")
                        if not isinstance(phase, str):
                            phase = None
                        if phase == "preparation" and "preparation_step" in receipt:
                            step = receipt["preparation_step"]
                            selected = preparation_logs.get(step) if isinstance(step, str) else None
                        else:
                            selected = {"preparation": "prepare-install-boot.qemu-startup.log",
                                        "restore": "resume-boot.qemu-startup.log"}.get(phase)
                        if selected:
                            names = [selected]
                            if selected.endswith("boot.qemu-startup.log"):
                                names.append(selected.removesuffix(".qemu-startup.log") + ".log")
                            for boot_name in names:
                                name = f"transactions/{boot_name}"
                                member = members_by_name.get(str(parent / name))
                                if member is not None and member.file_size <= 8 * 1024 * 1024:
                                    raw = archive.read(member)
                                    if raw.strip():
                                        excerpts.append((name, diagnostic_excerpt(raw)))
                                        break
                if excerpts:
                    # A measured command failure has a more precise cause than
                    # earlier guest probes. Preserve the full excerpt budget.
                    if any(name.endswith(("/transaction.stderr", "/transaction.stdout"))
                           for name, _ in excerpts):
                        candidates = []
                    else:
                        candidates = [parent / name for name in
                                      ("health-validation.log", "transactions.log")]
                for candidate in candidates:
                    member = members_by_name.get(str(candidate))
                    if member is None or member.file_size > 8 * 1024 * 1024:
                        continue
                    raw = archive.read(member)
                    if not raw.strip():
                        continue
                    excerpts.append((candidate.name, diagnostic_excerpt(raw)))
                if parent.name == "inventory" and not excerpts:
                    candidate = parent / "rows" / f"{case}.log"
                    member = members_by_name.get(str(candidate))
                    if member is not None and member.file_size <= 8 * 1024 * 1024:
                        raw = archive.read(member)
                        if raw.strip():
                            excerpts.append((candidate.name, diagnostic_excerpt(raw)))
                if not excerpts and case in ("lifecycle", "aarch64-lifecycle"):
                    # A setup failure can occur before boot.log or any guest
                    # case log exists. Report the latest available setup stage
                    # rather than an empty lifecycle diagnostic.
                    for name in ("image-setup.log", "controller-security.log",
                                 "controller-setup.log", "controller-pull.log",
                                 "engine-preflight.log"):
                        candidate = parent / name
                        member = members_by_name.get(str(candidate))
                        if member is None or member.file_size > 8 * 1024 * 1024:
                            continue
                        raw = archive.read(member)
                        if raw.strip():
                            excerpts.append((name, diagnostic_excerpt(raw)))
                            break
                if excerpts:
                    # Keep every selected stage visible within the existing
                    # issue budget. Redaction happens before truncation.
                    budget = (1300 - sum(len(name) + 4 for name, _ in excerpts)) // len(excerpts)
                    diagnostics[key] = "\n".join(
                        f"[{name}]\n" + excerpt.encode("utf-8")[-budget:].decode("utf-8", errors="ignore")
                        for name, excerpt in excerpts)
    return rows


def unexecuted_inventory_distros(rows):
    """Guest identities whose inventory rows were never started.

    A guest that dies before inventory writes one BLOCKED placeholder per
    requested case. Those placeholders are not separate failures. Promoting
    every one of them hides the lifecycle diagnosis and trips the issue cap.
    """
    grouped = {}
    failed_lifecycle = set()
    for row in rows:
        distro = row["distro"]
        guest = distro, row.get("arch", "x86_64")
        case_id = row["case_id"]
        if case_id in (f"qemu-{distro}-lifecycle", f"qemu-{distro}-aarch64-lifecycle"):
            if row["result"] in FAILURES:
                failed_lifecycle.add(guest)
            continue
        if case_id == "qemu-matrix-workflow" or case_id.startswith("qemu-matrix-"):
            continue
        grouped.setdefault(guest, []).append(row)
    return {
        guest for guest, group in grouped.items()
        if guest in failed_lifecycle and all(
            item["result"] == "BLOCKED" and item["exit_code"] == -1 and item["elapsed_seconds"] == 0
            for item in group
        )
    }


def projection(rows, verified_published):
    placeholders = unexecuted_inventory_distros(rows)
    selected = {}
    for row in rows:
        if ((row["distro"], row.get("arch", "x86_64")) in placeholders
                and row["result"] == "BLOCKED"
                and row["exit_code"] == -1 and row["elapsed_seconds"] == 0):
            continue
        key = row["case_id"], row["distro"], row.get("arch", "x86_64")
        if row["result"] in FAILURES:
            # The existing issue helper treats BLOCKED as context rather than
            # an issue. A failed prerequisite still needs a tracked diagnosis.
            selected[key] = dict(row, result="HARNESS_ERROR" if row["result"] == "BLOCKED" else row["result"])
        elif verified_published and row["result"] == "PASS" and key not in selected:
            selected[key] = row
    # Replace an aggregate only when detail covers every guest it names.
    # Independent guests and unknown matrix scope remain reportable.
    def aggregate(case_id):
        return case_id == "qemu-matrix-workflow" or (
            case_id.startswith("qemu-matrix-") and case_id.endswith("-workflow")
        )

    detailed = {(row["distro"], row.get("arch", "x86_64"))
                for row in selected.values()
                if not aggregate(row["case_id"])
                and row["case_id"] != "qemu-arm-runner-kvm-health"
                and row["result"] in FAILURES}

    def covered(row):
        if row["distro"] not in GUEST_DISTROS:
            # A matrix-wide receipt does not identify which guests failed.
            return False
        case_id = row["case_id"]
        if case_id == "qemu-matrix-all-workflow":
            arches = {"x86_64", "aarch64"}
        elif case_id == "qemu-matrix-arm-workflow":
            arches = {"aarch64"}
        elif case_id == "qemu-matrix-x86-workflow":
            arches = {"x86_64"}
        elif case_id == "qemu-matrix-workflow" and "arch" in row:
            arches = {row["arch"]}
        else:
            return False
        return all((row["distro"], arch) in detailed for arch in arches)

    selected = {key: row for key, row in selected.items()
                if not aggregate(row["case_id"]) or row["result"] not in FAILURES
                or not covered(row)}
    return list(selected.values())


def published_provenance(content, distro, revision):
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        members = [member for member in archive.infolist()
                   if member.filename == "provenance.json"]
        if len(members) != 1 or members[0].file_size > 4096:
            raise ValueError("missing or oversized published provenance")
        provenance = json.loads(archive.read(members[0]), object_pairs_hook=unique_object)
    if (not isinstance(provenance, dict)
            or type(provenance.get("staged")) is not bool
            or provenance.get("harness_revision") != revision
            or provenance.get("distro") != distro
            or provenance.get("arch") != "x86_64"):
        raise ValueError("published evidence provenance mismatch")
    if provenance["staged"]:
        return None
    if (provenance.get("artifact_attestation_verified") is not True
            or not isinstance(provenance.get("artifact_tag"), str)
            or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", provenance["artifact_tag"])
            or not isinstance(provenance.get("inventory_revision"), str)
            or not re.fullmatch(r"[0-9a-f]{40}", provenance["inventory_revision"])):
        raise ValueError("published evidence provenance mismatch")
    return provenance["artifact_tag"], provenance["inventory_revision"]


def published_inventory_admission(content, distro, policy):
    """Recheck the complete published profile against the trusted shard catalog."""
    # Reuse archive validation before consuming any selected input. No archive
    # path is extracted or executed; only fixed private filenames are written.
    _, snapshots = all_snapshots(policy)
    archive_rows(content, canonical_case_ids({"inventories": snapshots}))
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        members = archive.infolist()
        roots = {PurePosixPath(member.filename).parts[0] for member in members
                 if PurePosixPath(member.filename).parts
                 and PurePosixPath(member.filename).parts[0].startswith("run-")}
        if len(roots) != 1:
            raise ValueError("published guest lacks one run root")
        root = next(iter(roots))
        if not re.fullmatch(r"run-[A-Za-z0-9-]+", root):
            raise ValueError("invalid published run root")
        names = {"inventory": f"{root}/cases.tsv",
                 "results": f"{root}/inventory/results.json",
                 "summary": f"{root}/inventory/summary.json",
                 "admission": f"{root}/inventory-admission.json"}
        def read_input(name):
            matches = [member for member in members if member.filename == name]
            if len(matches) != 1 or matches[0].file_size > 1024 * 1024:
                raise ValueError("published guest lacks bounded CLI evidence")
            return archive.read(matches[0])
        inputs = {key: read_input(name) for key, name in names.items()}
        rows = json.loads(inputs["results"], object_pairs_hook=unique_object)
        if any(row["case_id"] == f"qemu-{distro}-doctor-network-live"
               and row["result"] == "PASS" for row in rows):
            for name in ("input-sha256.txt", "rows/doctor-network-live.stdout.log",
                         "rows/doctor-network-live.stderr.log"):
                inputs[name] = read_input(f"{root}/inventory/{name}")
        if any(PurePosixPath(member.filename).name == "results.json"
               and PurePosixPath(member.filename).parent.name != "transactions"
               and member.filename not in (names["results"], f"{root}/results.json")
               for member in members):
            raise ValueError("published guest has foreign result evidence")
        lifecycle = next((member for member in members if member.filename == f"{root}/results.json"), None)
        if lifecycle is not None:
            if lifecycle.file_size > 1024 * 1024:
                raise ValueError("published lifecycle exceeds limit")
            lifecycle_rows = json.loads(archive.read(lifecycle), object_pairs_hook=unique_object)
            if any(row["case_id"] != f"qemu-{distro}-lifecycle" for row in lifecycle_rows):
                raise ValueError("published lifecycle contains inventory cases")
    spec = importlib.util.spec_from_file_location(
        "qemu_inventory_admission", Path(__file__).with_name("check-qemu-inventory.py"))
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    with tempfile.TemporaryDirectory() as directory:
        paths = {}
        for key in ("inventory", "results", "summary"):
            paths[key] = Path(directory) / key
            paths[key].write_bytes(inputs[key])
        for name in ("input-sha256.txt", "rows/doctor-network-live.stdout.log",
                     "rows/doctor-network-live.stderr.log"):
            if name in inputs:
                target = Path(directory) / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(inputs[name])
        admitted = checker.admit(policy, paths["inventory"], paths["results"],
                                 paths["summary"], distro, "hermetic,qemu,container,network,pty")
    receipt = json.loads(inputs["admission"], object_pairs_hook=unique_object)
    # JSON type identity matters: Python otherwise considers True equal to 1.
    if json.dumps(receipt, sort_keys=True, allow_nan=False) != json.dumps(admitted, sort_keys=True, allow_nan=False):
        raise ValueError("published CLI inventory receipt mismatch")
    return admitted["passed"]


def complete_listing(payload, key):
    if (not isinstance(payload, dict) or type(payload.get("total_count")) is not int
            or not 0 <= payload["total_count"] <= 100
            or not isinstance(payload.get(key), list)
            or len(payload[key]) != payload["total_count"]
            or any(not isinstance(row, dict) for row in payload[key])):
        raise ValueError("incomplete GitHub listing")
    return payload[key]


def failed_lane_guests(jobs):
    guests = set()
    for job in jobs:
        if job.get("conclusion") not in ("failure", "timed_out", "cancelled", "action_required"):
            continue
        name = job["name"]
        arm = re.search(r"QEMU guest arm64 \((arch|debian|ubuntu|fedora)\)(?:\s*/|$)", name)
        x86 = re.search(r"(?:QEMU guest|Distro lane) \((arch|debian|debian-trixie|ubuntu|fedora)\)(?:\s*/|$)", name)
        if arm:
            guests.add((arm.group(1), "aarch64"))
        elif x86:
            guests.add((x86.group(1), "x86_64"))
    return guests


def failed_guest_receipts(jobs):
    return [dict(case_id=f"qemu-matrix-{'arm' if arch == 'aarch64' else 'x86'}-workflow",
                 distro=distro, arch=arch, result="HARNESS_ERROR", exit_code=1, elapsed_seconds=0)
            for distro, arch in sorted(failed_lane_guests(jobs))]


def case_job_details(run, jobs, row):
    source = "ci" if row["case_id"] == "ci-non-qemu-workflow" else "qemu-matrix"
    guest = ((row["distro"], row.get("arch", "x86_64"))
             if row["distro"] in GUEST_DISTROS
             and row["case_id"].startswith((f"qemu-{row['distro']}-", "qemu-matrix-")) else None)
    details = []
    for job in jobs:
        if job["conclusion"] in ("success", "skipped"):
            continue
        job_source = ("qemu-matrix" if run["path"] == ".github/workflows/qemu-matrix.yml"
                      or job["name"].startswith("QEMU behavioral verification") else "ci")
        if job_source != source or (guest is not None and guest not in failed_lane_guests([job])):
            continue
        if row["case_id"] == "qemu-arm-runner-kvm-health" and job["name"] != "ARM guest runner KVM health":
            continue
        name = re.sub(r"[^A-Za-z0-9 ._()/:-]", "?", job["name"])[:120]
        details.append(f"Job {job['id']}: {name} ({job['conclusion']})")
        for step in job.get("steps", [])[:100]:
            if step["conclusion"] not in ("success", "skipped"):
                name = re.sub(r"[^A-Za-z0-9 ._()/:-]", "?", step["name"])[:120]
                details.append(f"  Step {step['number']}: {name} ({step['conclusion']})")
    return details[:6]


def workflow_receipt(jobs, conclusion):
    """Return an aggregate identity scoped to the architecture actually run.

    ARM runner health is a prerequisite with its own identity: an x86 matrix
    success is not evidence that missing ARM KVM access recovered.
    """
    if not isinstance(jobs, list):
        raise ValueError("invalid workflow jobs")
    arm_health = None
    x86_selected = False
    arm_selected = False
    failed_lane_distros = set()
    for job in jobs:
        if not isinstance(job, dict) or not isinstance(job.get("name"), str):
            raise ValueError("invalid workflow job")
        name = job["name"]
        job_conclusion = job.get("conclusion")
        if job_conclusion in ("failure", "timed_out", "cancelled", "action_required"):
            lane = re.search(r"(?:^|/)\s*Distro lane \((arch|debian|debian-trixie|ubuntu|fedora)\)(?:\s*/|$)", name)
            if lane:
                failed_lane_distros.add(lane.group(1))
            else:
                arm_guest = re.search(r"QEMU guest arm64 \((arch|debian|ubuntu|fedora)\)", name)
                if arm_guest:
                    failed_lane_distros.add(arm_guest.group(1))
        if name == "ARM guest runner KVM health":
            arm_health = job_conclusion
            arm_selected = job_conclusion != "skipped"
        elif "QEMU guest arm64" in name:
            arm_selected = arm_selected or job_conclusion != "skipped"
        elif "QEMU guest (" in name:
            x86_selected = x86_selected or job_conclusion != "skipped"
    if arm_health not in (None, "success", "skipped"):
        return dict(case_id="qemu-arm-runner-kvm-health", distro="ubuntu",
                    result="HARNESS_ERROR", exit_code=1, elapsed_seconds=0)
    scope = "all" if arm_selected and x86_selected else "arm" if arm_selected else "x86"
    passed = conclusion == "success"
    if passed and not (x86_selected or arm_selected):
        return dict(case_id="qemu-matrix-workflow", distro="matrix",
                    result="HARNESS_ERROR", exit_code=1, elapsed_seconds=0)
    distro = next(iter(failed_lane_distros)) if len(failed_lane_distros) == 1 else "matrix"
    return dict(case_id=f"qemu-matrix-{scope}-workflow", distro=distro,
                result="PASS" if passed else "HARNESS_ERROR",
                exit_code=0 if passed else 1, elapsed_seconds=0)


def ci_non_qemu_failure(run, jobs):
    """Keep failed CI jobs distinct from the QEMU job's result."""
    return (run["path"] == ".github/workflows/ci.yml"
            and run["conclusion"] != "success"
            and (any(isinstance(job.get("name"), str)
                     and not job["name"].startswith("QEMU behavioral verification")
                     and job["name"] != "CI Success"
                     and job.get("conclusion") in ("failure", "timed_out", "cancelled", "action_required")
                     for job in jobs)
                 or (not qemu_job_failed(run, jobs)
                     and any(job.get("name") == "CI Success"
                             and job.get("conclusion") in ("failure", "timed_out", "action_required")
                             for job in jobs))))


def qemu_job_failed(run, jobs):
    return (run["path"] == ".github/workflows/qemu-matrix.yml"
            or any(isinstance(job.get("name"), str)
                   and job["name"].startswith("QEMU behavioral verification")
                   and job.get("conclusion") in ("failure", "timed_out", "cancelled", "action_required")
                   for job in jobs))


def bound_issue_updates(selected):
    """Bound issue creation without dropping the validated diagnostic catalog."""
    failures = [row for row in selected if row["result"] in FAILURES]
    if len(failures) <= 25:
        return selected, failures
    aggregate = dict(case_id="qemu-matrix-workflow", distro="matrix",
                     result="HARNESS_ERROR", exit_code=1, elapsed_seconds=0)
    passes = [row for row in selected
              if row["result"] == "PASS" and row["case_id"] != "qemu-matrix-workflow"]
    ci = [row for row in selected if row["case_id"] == "ci-non-qemu-workflow"]
    return [aggregate, *ci, *passes], failures


def write_failure_catalog(directory, run, repository, failures, evidence_error):
    directory.mkdir(parents=True, exist_ok=True)
    catalog = dict(schema_version=1, repository=repository, run_id=run["id"],
                   attempt=run["run_attempt"], source_sha=run["head_sha"],
                   evidence_invalid_or_unavailable=evidence_error, failures=failures)
    directory.joinpath("failures.json").write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")


def retained_guest_artifact(artifact, run, jobs):
    """Admit old evidence only for a successful guest job carried into a rerun."""
    name = artifact["name"]
    guest = re.fullmatch(r"qemu-(arm-)?evidence-(arch|debian|debian-trixie|ubuntu|fedora)", name)
    if guest is None or guest.group(1) and guest.group(2) == "debian-trixie":
        return False
    label = (f"QEMU guest arm64 ({guest.group(2)})" if guest.group(1)
             else f"QEMU guest ({guest.group(2)})")
    owners = [job for job in jobs if job.get("name", "").endswith(label)
              and job.get("conclusion") == "success"
              and job.get("started_at", "") < run["run_started_at"]
              and job.get("started_at", "") <= artifact["created_at"]
              <= job.get("completed_at", "")]
    return len(owners) == 1


def artifact_guest_identity(name):
    match = re.fullmatch(r"qemu-(arm-)?evidence-(arch|debian|debian-trixie|ubuntu|fedora)", name)
    if match is None or match.group(1) and match.group(2) == "debian-trixie":
        return None
    return match.group(2), "aarch64" if match.group(1) else "x86_64"


def main():
    repository = os.environ["GITHUB_REPOSITORY"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("invalid repository")
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    run_id = event["workflow_run"]["id"]
    if type(run_id) is not int or run_id <= 0:
        raise ValueError("invalid run ID")
    run = identity(event, json.loads(api(f"repos/{repository}/actions/runs/{run_id}")), repository)
    # Superseding an interactive run is not itself a product failure.
    if run["conclusion"] in ("cancelled", "skipped"):
        print("Cancelled/skipped run retained in Actions; no failure issue generated")
        return 0
    # A corrupt historical snapshot invalidates the whole reviewed catalog.
    # Keep the workflow failure reportable, but do not admit guest identities
    # using an incomplete allowlist or whatever happened to remain readable.
    evidence_error = False
    required_distros = None
    try:
        required_distros = run_guest_profile(repository, run['head_sha'])
        _, snapshots = all_snapshots(Path("tests/qemu-inventory-policy.json"))
        allowed_cases = canonical_case_ids({"inventories": snapshots})
    except (OSError, ValueError, KeyError, TypeError):
        allowed_cases = None
        evidence_error = True
    jobs_valid = False
    job_rows = []
    try:
        jobs = json.loads(api(f"repos/{repository}/actions/runs/{run_id}/attempts/{run['run_attempt']}/jobs?per_page=100"),
                          object_pairs_hook=unique_object)
        job_rows = complete_listing(jobs, "jobs")
        if len({job.get("id") for job in job_rows if type(job.get("id")) is int}) != len(job_rows):
            raise ValueError("duplicate or invalid workflow job identity")
        if any(not isinstance(job.get("name"), str)
               or type(job.get("id")) is not int or job["id"] <= 0
               or job.get("conclusion") not in ("success", "failure", "timed_out", "cancelled",
                                                 "action_required", "skipped", "neutral", "stale")
               or not isinstance(job.get("steps", []), list)
               for job in job_rows):
            raise ValueError("invalid workflow job identity")
        jobs_valid = True
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        job_rows = []
        evidence_error = True
    published_candidate = (run["conclusion"] == "success"
                           and run["path"] == ".github/workflows/qemu-matrix.yml"
                           and run["event"] in ("schedule", "workflow_dispatch")
                           and run["head_branch"] == "main")
    verified_published = False
    published_tag = None
    published_revision = None
    rows = []
    diagnostics = {}
    try:
        if allowed_cases is None or not jobs_valid or required_distros is None:
            raise ValueError("unvalidated policy catalog or job listing")
        listing = json.loads(api(f"repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100"),
                             object_pairs_hook=unique_object)
        artifacts = complete_listing(listing, "artifacts")
        guest_artifacts = set()
        published_artifacts = {}
        for artifact in artifacts:
            if artifact_guest_identity(artifact["name"]) is None and artifact["name"] != "qemu-workflow-report":
                continue
            # Re-run failed jobs retains successful jobs and their artifacts.
            # Carry those guests forward only when the latest job receipt still
            # owns the artifact; a replaced failed job cannot supply evidence.
            if (artifact["created_at"] < run["run_started_at"]
                    and not retained_guest_artifact(artifact, run, job_rows)):
                continue
            if artifact["expired"]:
                raise ValueError("expired artifact")
            if type(artifact["id"]) is not int or artifact["size_in_bytes"] > MAX_DOWNLOAD:
                raise ValueError("invalid artifact identity or size")
            guest = artifact_guest_identity(artifact["name"])
            if guest is not None and artifact["name"] in guest_artifacts:
                raise ValueError("duplicate guest artifact identity")
            content = api(f"repos/{repository}/actions/artifacts/{artifact['id']}/zip", MAX_DOWNLOAD)
            artifact_rows = archive_rows(content, allowed_cases, diagnostics,
                                         guest=guest, revision=run["head_sha"])
            if guest is not None and any(row["case_id"] == "qemu-matrix-workflow"
                                         for row in artifact_rows):
                raise ValueError("guest artifact contains workflow result")
            if guest is None and any(row["case_id"] != "qemu-matrix-workflow"
                                     for row in artifact_rows):
                raise ValueError("workflow report contains guest results")
            rows.extend(artifact_rows)
            guest_artifacts.add(artifact["name"])
            if published_candidate and artifact["name"].startswith("qemu-evidence-"):
                if artifact["name"] in published_artifacts:
                    raise ValueError("duplicate published guest artifact")
                published_artifacts[artifact["name"]] = content
        if run["path"] == ".github/workflows/ci.yml" and run["conclusion"] == "success":
            if (not {f"qemu-evidence-{distro}" for distro in required_distros} <= guest_artifacts
                    or not set(required_distros) <= {row["distro"] for row in rows}):
                raise ValueError("successful CI is missing required Linux guest evidence")
        if published_candidate:
            required = {f"qemu-evidence-{distro}" for distro in required_distros}
            if set(published_artifacts) == required:
                sources = {published_provenance(published_artifacts[f"qemu-evidence-{distro}"],
                                                distro, run["head_sha"]) for distro in required_distros}
                if None in sources and len(sources) > 1:
                    raise ValueError("mixed staged and published guest artifacts")
                if None not in sources:
                    if len(sources) != 1:
                        raise ValueError("published guest artifacts disagree on release tag")
                    source_tag, source_revision = next(iter(sources))
                    release_commit = json.loads(api(f"repos/{repository}/commits/{source_tag}"))
                    if release_commit.get("sha") != source_revision:
                        raise ValueError("published inventory revision does not match release tag")
                    latest = json.loads(api(f"repos/{repository}/releases/latest"))
                    admissions = [published_inventory_admission(
                        published_artifacts[f"qemu-evidence-{distro}"], distro,
                        Path("tests/qemu-inventory-policy.json")) for distro in required_distros]
                    verified_published = latest.get("tag_name") == source_tag and all(admissions)
                    published_tag = source_tag if verified_published else None
                    published_revision = source_revision if verified_published else None
        selected = projection(rows, verified_published)
    except (ValueError, OSError, KeyError, TypeError, zipfile.BadZipFile, subprocess.SubprocessError):
        selected = []
        evidence_error = True
    ci_failed = ci_non_qemu_failure(run, job_rows)
    qemu_failed = qemu_job_failed(run, job_rows)
    receipt = workflow_receipt(job_rows, run["conclusion"]) if jobs_valid else dict(
        case_id="qemu-matrix-workflow", distro="matrix", result="HARNESS_ERROR",
        exit_code=1, elapsed_seconds=0)
    if run["conclusion"] == "success" and receipt["result"] in FAILURES:
        selected = []
        verified_published = False
        evidence_error = True
    selected = [receipt if row["case_id"] == "qemu-matrix-workflow" else row for row in selected]
    if evidence_error:
        if qemu_failed or not ci_failed:
            guests = failed_guest_receipts(job_rows) if jobs_valid else []
            if len(guests) > 1 or (guests and receipt["case_id"] == "qemu-arm-runner-kvm-health"):
                selected.extend(guests)
                if receipt["case_id"] == "qemu-arm-runner-kvm-health":
                    selected.append(receipt)
            else:
                selected.append(workflow_receipt(job_rows, "failure")
                                if jobs_valid and receipt["case_id"] != "qemu-matrix-workflow" else receipt)
    elif qemu_failed and (failed_lane_guests(job_rows)
                          or receipt["case_id"] == "qemu-arm-runner-kvm-health"):
        health = [receipt] if receipt["case_id"] == "qemu-arm-runner-kvm-health" else []
        selected = projection([*selected, *health, *failed_guest_receipts(job_rows)], verified_published)
    elif run["conclusion"] != "success" and not any(row["result"] in FAILURES for row in selected):
        if qemu_failed or not ci_failed:
            selected.append(receipt)
    if ci_failed:
        selected.append(dict(case_id="ci-non-qemu-workflow", distro="matrix",
                             result="HARNESS_ERROR", exit_code=1, elapsed_seconds=0))
    if not selected:
        print("No authoritative case updates to report")
        return 0
    # Recheck after downloads: an operator may have rerun this ID meanwhile.
    identity(event, json.loads(api(f"repos/{repository}/actions/runs/{run_id}")), repository)
    if verified_published:
        current = json.loads(api(f"repos/{repository}/git/ref/heads/main"))
        latest = json.loads(api(f"repos/{repository}/releases/latest"))
        release_commit = json.loads(api(f"repos/{repository}/commits/{published_tag}"))
        if (current["object"]["sha"] != run["head_sha"]
                or latest.get("tag_name") != published_tag
                or release_commit.get("sha") != published_revision):
            selected = [row for row in selected if row["result"] != "PASS"]
            verified_published = False
        elif not evidence_error:
            selected.append(receipt)
    if not selected:
        print("No authoritative case updates to report")
        return 0
    selected, failure_catalog = bound_issue_updates(selected)
    report_directory = Path(os.environ["RUNNER_TEMP"]) / "qemu-issue-report"
    write_failure_catalog(report_directory, run, repository, failure_catalog, evidence_error)
    report_run = os.environ["GITHUB_RUN_ID"]
    if not report_run.isdecimal():
        raise ValueError("invalid reporter run ID")
    catalog_note = (
        f"Validated failing cases: {len(failure_catalog)}. "
        "Complete identities and observations: qemu-issue-report/failures.json.\n"
        f"Reporter artifacts: https://github.com/{repository}/actions/runs/{report_run}\n"
        "Artifact retention requested: 30 days (repository retention limits apply).\n"
    )
    if len(failure_catalog) > 25:
        catalog_note += "More than 25 cases failed; this aggregate bounds issue creation without discarding case evidence.\n"
    with tempfile.TemporaryDirectory() as directory:
        for row in selected:
            if row["result"] in FAILURES:
                arch = row.get("arch", "x86_64")
                evidence_name = (f"{row['distro']}-{row['case_id']}" if arch == "x86_64"
                                 else f"{row['distro']}-{arch}-{row['case_id']}")
                evidence = Path(directory) / evidence_name
                evidence.mkdir()
                evidence.joinpath("transcript.txt").write_text(
                    f"Commit: {run['head_sha']}\nEvent: {run['event']}\nAttempt: {run['run_attempt']}\n"
                    f"Guest architecture: {arch}\n"
                    f"Observed: {row['result']}, exit {row['exit_code']}, elapsed {row['elapsed_seconds']}s\n"
                    f"Evidence invalid/unavailable: {evidence_error}\n"
                    "Exit status alone does not establish the root cause. Inspect the linked run's logs and artifacts.\n"
                    + "\n".join(case_job_details(run, job_rows, row)) + "\n"
                    + "Case diagnostic (untrusted log excerpt, redacted by issue helper):\n"
                    + diagnostics.get((row["case_id"], row["distro"], arch),
                                      "No case log available; inspect linked artifacts.")
                    + "\n" + catalog_note)
        run_url = f"https://github.com/{repository}/actions/runs/{run_id}/attempts/{run['run_attempt']}"
        for source in ("qemu-matrix", "ci"):
            source_rows = [row for row in selected
                           if (row["case_id"] == "ci-non-qemu-workflow") == (source == "ci")]
            if not source_rows:
                continue
            results = Path(directory) / f"results-{source}.json"
            results.write_text(json.dumps(source_rows) + "\n")
            helper = ["bash", "scripts/qa-file-issue.sh", str(results), "--repo", repository,
                      "--source", source, "--run-url", run_url]
            if not verified_published:
                helper.append("--failures-only")
            subprocess.run(helper, check=True, timeout=180)
        sentry_rows = (selected if run["event"] == "pull_request" or evidence_error else
                       [row for row in selected if row["case_id"] == "ci-non-qemu-workflow"])
        if sentry_rows:
            results = Path(directory) / "results-all.json"
            results.write_text(json.dumps(sentry_rows) + "\n")
            subprocess.run(["bash", "scripts/report-smoke-sentry.sh", str(results)], check=True, timeout=20)
    print(f"Reported run {run_id}, attempt {run['run_attempt']}, commit {run['head_sha']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
