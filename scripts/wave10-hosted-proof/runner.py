"""Six sequential selected-library states. No workflow or dispatch capability."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import shutil
import signal
import stat
import subprocess
import threading
import time
import tomllib


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, value):
    with path.open("xb") as stream:
        stream.write((json.dumps(value, indent=2) + "\n").encode())
        stream.flush()
        os.fsync(stream.fileno())


def regular(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "regular single-link file required")
    return info


def sample(target, reserve, ceiling):
    started = time.monotonic()
    root = target.lstat()
    require(stat.S_ISDIR(root.st_mode), "target root must be a directory")

    def verify_root():
        current = target.lstat()
        require(stat.S_ISDIR(current.st_mode) and (current.st_dev, current.st_ino) ==
                (root.st_dev, root.st_ino), "target root identity changed")

    total = entries = vanished_entries = vanished_directories = 0
    pending = [target]
    while pending:
        require(time.monotonic() - started < 3, "target census incomplete")
        directory = pending.pop()
        try:
            scan = os.scandir(directory)
        except FileNotFoundError:
            if directory == target:
                raise
            verify_root()
            vanished_directories += 1
            continue
        with scan as iterator:
            for item in iterator:
                entries += 1
                require(entries <= 300000 and time.monotonic() - started < 3,
                        "target census incomplete")
                try:
                    info = item.stat(follow_symlinks=False)
                except FileNotFoundError:
                    verify_root()
                    vanished_entries += 1
                    continue
                if stat.S_ISDIR(info.st_mode):
                    pending.append(Path(item.path))
                else:
                    total += getattr(info, "st_blocks", (info.st_size + 511) // 512) * 512
    verify_root()
    require(time.monotonic() - started < 3, "target census incomplete")
    value = {"at_monotonic": time.monotonic(), "target_bytes": total,
             "host_free_bytes": shutil.disk_usage(target).free, "entries": entries,
             "vanished_entries": vanished_entries, "vanished_directories": vanished_directories}
    if total > ceiling:
        return value, "target budget exceeded"
    if value["host_free_bytes"] < reserve:
        return value, "host reserve breached"
    return value, None


def capture(argv, cwd, output, label, timeout, target, limits, accounting, env):
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    events = queue.Queue(maxsize=8)
    stop = threading.Event()
    readers = []
    finished = set()
    samples = []
    started = time.monotonic()
    process = None
    exit_code = None
    error = None
    closure = {"direct_child_waited": False, "group_absent": None}

    def reader(name, stream):
        try:
            while not stop.is_set():
                block = stream.read1(65536)
                while not stop.is_set():
                    try:
                        events.put((name, block, None), timeout=0.05)
                        break
                    except queue.Full:
                        continue
                if not block:
                    return
        except Exception as exc:
            events.put((name, b"", str(exc)))
        finally:
            stream.close()

    try:
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=os.name == "posix")
        for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            thread = threading.Thread(target=reader, args=(name, stream), daemon=True)
            thread.start()
            readers.append(thread)
        deadline = min(started + timeout, accounting["deadline"])
        next_sample = 0
        terminal = False
        while len(finished) != 2 or not terminal:
            now = time.monotonic()
            require(now < deadline, "command deadline exceeded")
            if now >= next_sample:
                observed, refusal = sample(target, limits["reserve_bytes"], limits["target_bytes"])
                samples.append(observed)
                require(refusal is None, refusal)
                next_sample = time.monotonic() + limits["sample_seconds"]
            if os.name == "posix":
                # Keep the owned leader unreaped until its process group is closed.
                terminal = os.waitid(os.P_PID, process.pid,
                    os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
            else:
                terminal = process.poll() is not None
            try:
                name, block, pipe_error = events.get(timeout=0.02)
            except queue.Empty:
                continue
            require(pipe_error is None, "capture reader error: " + str(pipe_error))
            if not block:
                finished.add(name)
                continue
            remaining = min(4 * 1024**2 - len(buffers[name]),
                            limits["raw_bytes"] - accounting["bytes"])
            buffers[name].extend(block[:max(0, remaining)])
            accounting["bytes"] += min(len(block), max(0, remaining))
            require(len(block) <= remaining, "raw output budget exceeded; partial evidence retained")
    except Exception as exc:
        error = str(exc)
    finally:
        if process is not None:
            if os.name == "posix":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    closure["group_stop"] = "already_absent"
                except OSError as exc:
                    error = (error or "") + " process-group stop: " + str(exc)
            elif process.poll() is None:
                process.kill()
            try:
                exit_code = process.wait(timeout=5)
                closure["direct_child_waited"] = True
            except subprocess.TimeoutExpired:
                error = (error or "") + " direct child did not close"
            if os.name == "posix":
                end = time.monotonic() + 5
                while time.monotonic() < end:
                    try:
                        os.killpg(process.pid, 0)
                    except ProcessLookupError:
                        closure["group_absent"] = True
                        break
                    time.sleep(0.02)
                require_closed = closure["group_absent"] is True
                if not require_closed:
                    error = (error or "") + " process-group closure unknown"
            drain_end = time.monotonic() + 2
            while len(finished) != 2 and time.monotonic() < drain_end:
                try:
                    name, block, pipe_error = events.get(timeout=0.02)
                except queue.Empty:
                    continue
                if pipe_error:
                    error = (error or "") + " capture drain error: " + pipe_error
                if not block:
                    finished.add(name)
                    continue
                remaining = min(4 * 1024**2 - len(buffers[name]),
                                limits["raw_bytes"] - accounting["bytes"])
                buffers[name].extend(block[:max(0, remaining)])
                accounting["bytes"] += min(len(block), max(0, remaining))
                if len(block) > remaining:
                    error = (error or "") + " raw output budget exceeded during drain"
            stop.set()
            for thread in readers:
                thread.join(timeout=2)
            if any(thread.is_alive() for thread in readers):
                error = (error or "") + " pipe reader closure unknown"
            closure["pipe_readers_closed"] = [not thread.is_alive() for thread in readers]
            for thread, stream in zip(readers, (process.stdout, process.stderr)):
                if not thread.is_alive():
                    stream.close()
        channels = {}
        for name, data in buffers.items():
            path = output / (label + "." + name)
            with path.open("xb") as stream:
                stream.write(data)
            channels[name] = {"path": path.name, "bytes": len(data), "sha256": digest(data)}
        record = {"argv": argv, "cwd": str(cwd), "pid": process.pid if process else None,
                  "exit_code": exit_code, "error": error, "elapsed_seconds": time.monotonic() - started,
                  "complete": error is None and len(finished) == 2,
                  "closure": closure, "samples": samples, **channels}
        save(output / (label + ".command.json"), record)
    require(error is None, error)
    return record, bytes(buffers["stdout"]), bytes(buffers["stderr"])


def artifact(raw, repo, target, plan):
    items = [json.loads(line) for line in raw.splitlines() if line]
    require(sum(x.get("reason") == "build-finished" and x.get("success") is True for x in items) == 1,
            "build did not finish successfully")
    candidates = [x for x in items if x.get("reason") == "compiler-artifact"
                  and x.get("target", {}).get("name") == "omg_lib" and x.get("executable")]
    require(len(candidates) == 1, "ambiguous owning library artifact")
    row = candidates[0]
    manifest = repo / "Cargo.toml"
    require(row.get("manifest_path") == str(manifest), "root manifest identity")
    manifest_raw = manifest.read_bytes()
    require(digest(manifest_raw) == plan["source_pins"]["Cargo.toml"], "root manifest pin")
    package = tomllib.loads(manifest_raw.decode())["package"]
    require(package.get("name") == "omg" and package.get("version") == plan["package_version"],
            "root manifest package")
    identities = {f"path+{repo.as_uri()}#omg@{plan['package_version']}"}
    if repo.name == "omg":
        identities.add(f"path+{repo.as_uri()}#{plan['package_version']}")
    require(row["package_id"] in identities, "root package identity")
    require(row["target"]["kind"] == ["lib"] and Path(row["target"]["src_path"]).resolve() == repo / "src/lib.rs",
            "owning library source identity")
    require(row["fresh"] is False, "fresh library compiler artifact required")
    require(all(row["profile"].get(k) == v for k, v in plan["profile"].items()), "library profile mismatch")
    features = set(row["features"])
    require({"arch", "pgp", "license"} <= features and
            not features & {"debian", "debian-pure", "fedora", "macos"}, "library feature graph mismatch")
    binary = Path(row["executable"])
    require(binary.is_absolute() and binary.resolve() == binary and binary.is_relative_to(target),
            "executable outside owned target")
    regular(binary)
    with binary.open("rb") as stream:
        require(stream.read(4) == b"\x7fELF", "owning executable is not ELF")
    return binary, row


def discovery(raw, selectors):
    text = raw.decode()
    rows = [line[:-6] for line in text.splitlines() if line.endswith(": test")]
    for selector in selectors:
        require(rows.count(selector) == 1, "compiler discovery missing or duplicate selected test")
    return {"all_listed_tests": len(rows), "selected_exactly_once": selectors}


def body_outcome(record, raw, stderr, selector, red):
    text = raw.decode()
    require(not stderr, "unexpected selected test stderr")
    require(text.count("running 1 test") == 1, "body selection is not one test")
    expected_red = red is not None and selector == red["selector"]
    marker = f"test {selector} ... {'FAILED' if expected_red else 'ok'}"
    require(text.count(marker) == 1, "unexpected test result/name")
    counts = re.findall(r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured;", text)
    want = ("FAILED", "0", "1", "0", "0") if expected_red else ("ok", "1", "0", "0", "0")
    require(counts == [want], "unexpected selected body counts or ignored test")
    require(record["exit_code"] == (101 if expected_red else 0), "unexpected selected body exit")
    if expected_red:
        require("HARNESS" not in text and text.count("panicked at ") == 1 and
                re.search(r"(?m)^thread '" + re.escape(selector) + r"'(?: \([0-9]+\))? panicked at ", text), "intended RED diagnostic is setup/ambiguous")
        location = re.escape(red["path"])
        require(re.search(r"panicked at (?:" + location + r"|" + re.escape(str(red["absolute_path"])) + r"):\d+:\d+:", text),
                "intended RED diagnostic source")
        require("assertion `left == right` failed" in text, "intended RED diagnostic assertion")
        if red["kind"] == "gt":
            require("example-lib>1.0 / 2.0-1" in text and re.search(r"left:\s*false\s+right:\s*true", text),
                    "intended RED diagnostic false versus true")
        else:
            require(re.search(r"left:\s*0\s+right:\s*2", text), "intended RED diagnostic zero versus two")
    return "intended_red" if expected_red else "passed"


def run(repo, output, plan, commands, limits=None):
    repo, output = Path(repo).resolve(), Path(output).resolve()
    limits = limits or {"build": 900, "rebuild": 240, "list": 15, "body": 5, "total": 3000,
                        "target_bytes": 25 * 1024**3, "reserve_bytes": 12 * 1024**3,
                        "sample_seconds": 2, "raw_bytes": 32 * 1024**2}
    target = Path(commands.target).resolve() if hasattr(commands, "target") else output.parent / "target"
    output.mkdir(exist_ok=False)
    result = {"state": "HOLD", "evidence_scope": commands.evidence_scope, "states": [], "error": None,
              "restoration": None, "limits": limits}
    admitted = False
    accounting = {"bytes": 0, "deadline": time.monotonic() + limits["total"]}
    owned_paths = set(plan["variants"][plan["restore"]])

    def check_sources(expected):
        if hasattr(commands, "check_checkout"):
            commands.check_checkout()
        for path, wanted in getattr(commands, "provider_pins", {}).items():
            require(file_digest(Path(path)) == wanted, "toolchain provider drift: " + path)
        for path, wanted in plan["source_pins"].items():
            file = repo / path
            regular(file)
            require(digest(file.read_bytes()) == wanted, "non-overlay source drift: " + path)
        for path, row in expected.items():
            file = repo / path
            regular(file)
            require(digest(file.read_bytes()) == row["sha256"], "overlay source drift: " + path)

    def apply(variant):
        for path, row in variant.items():
            data = bytes.fromhex(row["bytes_hex"])
            require(digest(data) == row["sha256"], "variant payload hash")
            file = repo / path
            require(file.resolve() == file and file.is_relative_to(repo), "overlay path identity")
            regular(file)
            file.write_bytes(data)
        check_sources(variant)

    try:
        require(len(set(plan["selectors"])) == len(plan["selectors"]) == 20, "exact twenty selectors required")
        require(len(plan["states"]) == 6, "six states required")
        require(all(set(v) == owned_paths for v in plan["variants"].values()), "variant owner mismatch")
        current = plan["variants"][plan["states"][0]["variant"]]
        # A hosted branch may begin with the reviewed stronger tests already applied.
        actual = {n: digest((repo / n).read_bytes()) for n in owned_paths}
        choices = [v for v in (current, plan["variants"][plan["restore"]])
                   if all(actual[n] == row["sha256"] for n, row in v.items())]
        require(len(choices) >= 1, "initial overlay identity is neither old nor reviewed stronger")
        check_sources(choices[0])
        current = choices[0]
        require(not target.exists(), "target must be fresh and job-owned")
        target.mkdir(parents=True)
        require(shutil.disk_usage(target).free >= limits["target_bytes"] + limits["reserve_bytes"],
                "insufficient target growth plus reserve")
        admitted = True
        env = os.environ.copy()
        env.update(getattr(commands, "environment", {}))
        save(output / "admission.json", {"initial_overlay_hashes": actual, "target": str(target),
             "scope": commands.evidence_scope, "source_pins": plan["source_pins"], "environment": getattr(commands, "environment", {})})
        for index, state in enumerate(plan["states"]):
            require(time.monotonic() < accounting["deadline"], "aggregate deadline exceeded")
            check_sources(current)
            variant = plan["variants"][state["variant"]]
            result["active_state"] = state["id"]
            apply(variant)
            current = variant
            name = state["id"]
            label = f"{index:02d}-{name}"
            build, raw, _ = capture(commands.command("build", name), repo, output, label + "-build",
                limits["build"] if index == 0 else limits["rebuild"], target, limits, accounting, env)
            require(build["exit_code"] == 0, "build command failure")
            check_sources(variant)
            binary, row = artifact(raw, repo, target, plan)
            binary_hash = file_digest(binary)
            result["last_validated_compile_state"] = name
            result["last_executable"] = {"path": str(binary), "sha256": binary_hash}
            save(output / (label + "-compiler-identity.json"), {"source_variant": state["variant"],
                "compiler_artifact": row, "executable_sha256": binary_hash})
            listed, raw, _ = capture(commands.command("list", name, binary), repo, output, label + "-list",
                limits["list"], target, limits, accounting, env)
            require(listed["exit_code"] == 0, "list command failure")
            discovered = discovery(raw, plan["selectors"])
            tally = {"id": name, "passed": 0, "intended_red": 0, "binary_sha256": binary_hash,
                     "compiler_artifact": row, "discovery": discovered, "outcomes": []}
            save(output / (label + "-identity.json"), {"sources": variant, "binary_sha256": binary_hash,
                 "compiler_artifact": row, "discovery": discovered})
            for number, selector in enumerate(plan["selectors"]):
                record, raw, stderr = capture(commands.command("body", name, binary, selector), repo, output,
                    label + f"-test-{number:02d}", limits["body"], target, limits, accounting, env)
                red = dict(state["red"]) if state["red"] else None
                if red:
                    red["absolute_path"] = repo / red["path"]
                outcome = body_outcome(record, raw, stderr, selector, red)
                tally[outcome] += 1
                tally["outcomes"].append({"selector": selector, "outcome": outcome})
                save(output / (label + f"-test-{number:02d}-outcome.json"), tally["outcomes"][-1])
                check_sources(variant)
                require(file_digest(binary) == binary_hash, "executable drift")
            require((tally["passed"], tally["intended_red"]) == ((19, 1) if state["red"] else (20, 0)),
                    "state outcome mismatch")
            save(output / (label + "-state.json"), tally)
            result["states"].append(tally)
        result["state"] = "CAPTURED_PENDING_ROOT_REVIEW"
    except Exception as exc:
        result["error"] = str(exc)
    finally:
        if admitted:
            try:
                before_restore = {n: file_digest(repo / n) for n in owned_paths}
                save(output / "pre-restoration.json", {"actual_overlay_hashes": before_restore})
                require(all(value in {v[n]["sha256"] for v in plan["variants"].values()}
                            for n, value in before_restore.items()),
                        "unknown overlay bytes preserved; restoration requires root review")
                apply(plan["variants"][plan["restore"]])
                result["restoration"] = {"stronger_sources_restored": True,
                    "source_hashes": {n: digest((repo / n).read_bytes()) for n in owned_paths},
                    "last_validated_compile_state": result.get("last_validated_compile_state"),
                    "active_state_at_termination": result.get("active_state"),
                    "current_target_elf_sha256": file_digest(Path(result["last_executable"]["path"]))
                        if result.get("last_executable") and Path(result["last_executable"]["path"]).is_file() else None,
                    "failed_or_early_state_executable_quarantined": result["state"] == "HOLD"}
            except Exception as exc:
                result["state"] = "HOLD"
                result["error"] = (result["error"] or "") + " restoration: " + str(exc)
        result["raw_bytes"] = accounting["bytes"]
        save(output / "result.json", result)
    return result


class CargoCommands:
    evidence_scope = "HOSTED_ARCH_SELECTED_RUST_SUBJECT_PENDING_ACTUAL_EXECUTION"

    def __init__(self, cargo, rustc, target, provider_pins):
        self.cargo, self.target = str(cargo), target
        self.provider_pins = provider_pins
        self.environment = {"CARGO_TARGET_DIR": str(target), "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0",
            "CARGO_PROFILE_TEST_LTO": "off", "CARGO_TERM_COLOR": "never", "RUST_BACKTRACE": "0",
            "RUSTC": str(rustc)}

    def command(self, phase, state, binary=None, selector=None):
        if phase == "build":
            return [self.cargo, "test", "--lib", "--no-default-features", "--features", "arch,pgp,license",
                    "--locked", "--profile", "test", "--no-run", "--message-format=json-render-diagnostics"]
        if phase == "list":
            return [str(binary), "--list", "--format", "terse", "--color", "never"]
        return [str(binary), selector, "--exact", "--test-threads=1", "--color", "never"]


def checkout_paths(repo, *args):
    raw = subprocess.run(["git", "--no-optional-locks", *args], cwd=repo,
        check=True, capture_output=True, timeout=10).stdout
    return [item.decode() for item in raw.split(b"\0") if item]


def check_checkout(repo, published_pins, policy_repo_path, policy_sha256, owned_paths):
    require(not checkout_paths(repo, "ls-files", "--others", "-z"), "untracked checkout inputs refused")
    require(not checkout_paths(repo, "diff", "--cached", "--name-only", "-z", "HEAD"), "staged checkout inputs refused")
    changed = set(checkout_paths(repo, "diff", "--name-only", "-z", "HEAD"))
    require(changed <= set(owned_paths), "unexpected working source delta outside published policy")
    for name, wanted in {**published_pins, policy_repo_path: policy_sha256}.items():
        require(not Path(name).is_absolute(), "published path must be relative")
        file = repo / name
        require(file.resolve() == file and file.is_relative_to(repo), "published path identity")
        if name not in owned_paths:
            regular(file)
            require(file_digest(file) == wanted, "published source drift: " + name)


def runtime_inputs(repo, policy_path, binding_path, plan_path):
    repo, policy_path, binding_path, plan_path = (Path(x).resolve() for x in (repo, policy_path, binding_path, plan_path))
    require(policy_path.is_relative_to(repo), "reviewed policy must be the tracked checkout document")
    require(not binding_path.is_relative_to(repo), "runtime binding must be outside Git checkout")
    policy = json.loads(policy_path.read_bytes())
    binding = json.loads(binding_path.read_bytes())
    plan = json.loads(plan_path.read_bytes())
    require(policy["state"] == "ROOT_REVIEWED_POLICY_RUNTIME_UNOBSERVED", "reviewed static policy required")
    require(binding["state"] == "RUNTIME_BOUND_UNOBSERVED_SUBJECT_PENDING_ROOT_REVIEW", "observed runtime binding required")
    policy_hash = file_digest(policy_path)
    require(binding["policy_sha256"] == policy_hash, "runtime policy binding mismatch")
    require(policy["plan_sha256"] == file_digest(plan_path), "published plan mismatch")
    require(policy["total_seconds"] == 3000, "reviewed aggregate budget mismatch")
    require((policy["base_source_head"], policy["base_source_tree"]) ==
            (plan["base_source_head"], plan["base_source_tree"]), "reviewed base identity mismatch")
    require(repo == Path(os.environ["GITHUB_WORKSPACE"]).resolve(), "hosted workspace identity")
    require(re.fullmatch(r"[0-9a-f]{40}", os.environ["GITHUB_SHA"]) and
            binding["event_sha"] == os.environ["GITHUB_SHA"], "event source binding mismatch")
    for key, env_key in (("event_name", "GITHUB_EVENT_NAME"), ("branch_ref", "GITHUB_REF")):
        require(policy[key] == binding[key] == os.environ[env_key], "event/ref policy mismatch")
    checkout = subprocess.run(["git", "--no-optional-locks", "rev-parse", "HEAD", "HEAD^{tree}"], cwd=repo,
        check=True, capture_output=True, text=True, timeout=10).stdout.splitlines()
    require(checkout == [binding["event_sha"], binding["event_tree"]], "actual checkout identity")
    base_tree = subprocess.run(["git", "--no-optional-locks", "rev-parse", policy["base_source_head"] + "^{tree}"],
        cwd=repo, check=True, capture_output=True, text=True, timeout=10).stdout.strip()
    require(base_tree == policy["base_source_tree"], "actual base tree identity")
    policy_repo_path = policy_path.relative_to(repo).as_posix()
    published = policy["published_files"]
    require(policy_repo_path not in published, "policy cannot contain its own hash")
    require(policy["operator_sha256"] in published.values() and
            policy["source_manifest_sha256"] in published.values() and
            policy["plan_sha256"] in published.values(), "published proof input pins missing")
    owned = set(plan["variants"]["strong"])
    delta = set(checkout_paths(repo, "diff", "--name-only", "-z", policy["base_source_head"], "HEAD"))
    require(delta <= set(published) | owned | {policy_repo_path}, "published source delta outside reviewed policy")
    check_checkout(repo, published, policy_repo_path, policy_hash, owned)
    providers = {}
    for label, key in (("Cargo", "cargo"), ("rustc", "rustc")):
        path = Path(binding[key + "_path"])
        require(path.is_absolute() and file_digest(path) == binding[key + "_sha256"], label + " provider pin")
        providers[str(path)] = binding[key + "_sha256"]
    require(binding["exclusive_checkout_and_target"] is True, "exclusive actor coordination required")
    return {"checkout": checkout, "provider_pins": providers, "published_pins": published,
            "policy_repo_path": policy_repo_path, "policy_sha256": policy_hash,
            "binding_sha256": file_digest(binding_path)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--root-policy", type=Path, required=True)
    parser.add_argument("--runtime-binding", type=Path, required=True)
    args = parser.parse_args()
    require(os.name == "posix", "hosted Linux only; no local Windows Rust execution")
    repo = args.repo.resolve()
    joined = runtime_inputs(repo, args.root_policy, args.runtime_binding, args.plan)
    policy = json.loads(args.root_policy.read_bytes())
    binding = json.loads(args.runtime_binding.read_bytes())
    plan = json.loads(args.plan.read_bytes())
    require(file_digest(Path(__file__)) == policy["operator_sha256"], "actual operator source identity")
    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve()
    require(all(path.resolve().is_relative_to(runner_temp)
                for path in (args.target, args.output, args.runtime_binding)), "job-owned target/evidence/binding required")
    cargo, rustc = Path(binding["cargo_path"]), Path(binding["rustc_path"])
    for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
                "CARGO_PROFILE_TEST_DEBUG", "CARGO_PROFILE_TEST_OPT_LEVEL", "CARGO_PROFILE_TEST_DEBUG_ASSERTIONS",
                "CARGO_PROFILE_TEST_OVERFLOW_CHECKS"):
        require(not os.environ.get(key), "unexpected compiler/profile override: " + key)
    pins = {**joined["provider_pins"], str(args.root_policy.resolve()): joined["policy_sha256"],
            str(args.runtime_binding.resolve()): joined["binding_sha256"]}
    commands = CargoCommands(cargo, rustc, args.target.resolve(), pins)
    commands.check_checkout = lambda: check_checkout(repo, joined["published_pins"],
        joined["policy_repo_path"], joined["policy_sha256"], set(plan["variants"]["strong"]))
    result = run(repo, args.output, plan, commands)
    save(args.output / "hosted-context.json", {"checkout": joined["checkout"], "actor_uid": os.getuid(),
         "actor_gid": os.getgid(), "groups": os.getgroups(), "uname": list(os.uname()),
         "policy_sha256": joined["policy_sha256"], "runtime_binding_sha256": joined["binding_sha256"],
         "binding_scope": "MEASURED_RUNTIME_NOT_PREOBSERVED_ROOT_APPROVAL",
         "cargo_path": str(cargo), "cargo_before_sha256": binding["cargo_sha256"],
         "cargo_after_sha256": file_digest(cargo), "rustc_path": str(rustc),
         "rustc_before_sha256": binding["rustc_sha256"], "rustc_after_sha256": file_digest(rustc)})
    require(file_digest(cargo) == binding["cargo_sha256"] and
            file_digest(rustc) == binding["rustc_sha256"], "toolchain provider changed")
    raise SystemExit(0 if result["state"] == "CAPTURED_PENDING_ROOT_REVIEW" else 1)


if __name__ == "__main__":
    main()
