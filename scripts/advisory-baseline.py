"""Advance server-owned CVE publisher proof or refuse an unready release."""

import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.request

ORIGIN = "https://omg-advisories.latham.workers.dev"
BINDING_FILE = Path(__file__).resolve().parent.parent / ".github/advisory-baseline.json"
PROOF_PATH = "/internal/baseline/verify"
STATUS_PATH = "/v1/status"
MAX_BODY = 64 * 1024
STOP_PHASES = ("verified", "awaiting_import", "awaiting_catchup")
MAX_PROOF_STEPS = 256
PROOF_SECONDS = 8 * 60
LEASE_ATTEMPTS = 5

_spec = importlib.util.spec_from_file_location("runtime_refresh_transport", Path(__file__).with_name("refresh-runtime-advisories.py"))
_transport = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_transport)


def _object(value):
    if type(value) is not dict:
        raise ValueError("expected object")
    return value


def _integer(value, maximum=1_000_000):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("invalid bounded count")
    return value


def _json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate response field")
            result[key] = value
        return result
    return _object(json.loads(raw.decode("utf-8"), object_pairs_hook=unique))


def load_binding(path=BINDING_FILE):
    info = path.lstat()
    if path.is_symlink() or not path.is_file() or info.st_size > 16 * 1024:
        raise ValueError("invalid binding file")
    state = _json(path.read_bytes())
    baseline, publisher = _object(state.get("baseline")), _object(state.get("publisher"))
    digest = state.get("digest")
    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest) or baseline.get("digest") != digest or baseline.get("endpoint") != ORIGIN:
        raise ValueError("invalid baseline binding")
    if not isinstance(baseline.get("instance_id"), str) or not re.fullmatch(r"[a-f0-9]{32}", baseline["instance_id"]) or not isinstance(baseline.get("session_id"), str) or not re.fullmatch(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", baseline["session_id"]):
        raise ValueError("invalid baseline session binding")
    if type(state.get("next_entry")) is not int or state["next_entry"] != 0 or type(state.get("accepted")) is not int or state["accepted"] != 0 or state.get("exhausted") is not False or "finished_at" not in state or state["finished_at"] is not None:
        raise ValueError("repository binding must contain a zero checkpoint")
    tag = publisher.get("release_tag")
    match = re.fullmatch(r"cve_(\d{4}-\d{2}-\d{2})_0000Z", tag or "")
    if not match or publisher.get("asset") not in (f"{match[1]}_all_CVEs_at_midnight.zip", f"{match[1]}_all_CVEs_at_midnight.zip.zip"):
        raise ValueError("invalid baseline publisher release")
    datetime.strptime(match[1], "%Y-%m-%d")
    return {"digest": digest, "endpoint": ORIGIN, "instance_id": baseline["instance_id"], "session_id": baseline["session_id"], "release_tag": tag, "asset": publisher["asset"]}


def request_json(path, *, body=None, secret=None, opener=None, timeout=40):
    if path not in (PROOF_PATH, STATUS_PATH) or (path == PROOF_PATH) != (body is not None):
        raise ValueError("invalid fixed advisory operation")
    headers = {"Cache-Control": "no-cache", "User-Agent": "omg-advisory-baseline/1.0"}
    if body is not None:
        headers.update({"Authorization": f"Bearer {secret}", "Content-Type": "application/json"})
    request = urllib.request.Request(ORIGIN + path, data=json.dumps(body).encode("utf-8") if body is not None else None, headers=headers, method="POST" if body is not None else "GET")
    with (opener or _transport.secure_opener()).open(request, timeout=timeout) as response:
        if response.status != 200 or response.geturl() != ORIGIN + path:
            raise ValueError("invalid fixed-origin response")
        raw = response.read(MAX_BODY + 1)
    if len(raw) > MAX_BODY or (secret and secret.encode() in raw) or (body and body["github_token"].encode() in raw):
        raise ValueError("invalid response bounds or credential echo")
    return _json(raw)


def proof_progress(reply, binding):
    """Match the canonical operator.ts proofProgress contract; never certify locally."""
    reply = _object(reply)
    if type(reply.get("schema_version")) is not int or reply["schema_version"] != 1 or any(reply.get(key) != binding[key] for key in ("digest", "release_tag", "asset")) or not isinstance(reply.get("commit_sha"), str) or not re.fullmatch(r"[a-f0-9]{40}", reply["commit_sha"]):
        raise ValueError("publisher proof binding mismatch")
    phase = reply.get("phase")
    expected, verified, pending = (_integer(reply.get(key)) for key in ("expected_count", "verified_count", "pending_trees"))
    if phase not in ("traversing", "reconciling", *STOP_PHASES) or verified > expected or type(reply.get("archive_verified")) is not bool:
        raise ValueError("invalid proof progress")
    if reply["archive_verified"] != (phase == "verified") or (phase == "verified" and (expected == 0 or verified != expected or pending != 0)):
        raise ValueError("inconsistent server certification")
    return {"phase": phase, "expected_count": expected, "verified_count": verified, "pending_trees": pending}


def warm(binding, github_token, secret, *, max_steps=MAX_PROOF_STEPS, opener=None, emit=print, clock=time.monotonic, sleep=time.sleep):
    if type(max_steps) is not int or not 1 <= max_steps <= MAX_PROOF_STEPS or not re.fullmatch(r"ghs_[A-Za-z0-9._-]{20,2044}", github_token or "") or not re.fullmatch(r"[A-Za-z0-9_-]{32,256}", secret or ""):
        raise ValueError("invalid proof operator bounds or credentials")
    body = dict(binding, github_token=github_token)
    deadline = clock() + PROOF_SECONDS
    progress = None
    completed = 0

    def exhausted():
        if progress is None:
            raise TimeoutError("proof budget expired before observing server progress")
        emit(json.dumps(dict(progress, step=completed, budget_exhausted=1)))
        return progress

    for step in range(max_steps):
        for attempt in range(LEASE_ATTEMPTS):
            remaining = deadline - clock()
            if remaining <= 0:
                return exhausted()
            try:
                reply = request_json(PROOF_PATH, body=body, secret=secret, opener=opener, timeout=min(40, remaining))
                break
            except urllib.error.HTTPError as error:
                if error.code != 409 or attempt + 1 == LEASE_ATTEMPTS:
                    raise
                error.close()
                # Five attempts, with 1/2/4/8-second backoffs for Cron lease contention.
                delay = 2 ** attempt
                if deadline - clock() <= delay:
                    return exhausted()
                sleep(delay)
        progress = proof_progress(reply, binding)
        completed = step + 1
        emit(json.dumps(dict(progress, step=step + 1)))
        if progress["phase"] in STOP_PHASES:
            return progress
    return progress


def _timestamp(value):
    if not isinstance(value, str) or len(value) > 64 or not value.endswith("Z"):
        raise ValueError("invalid source timestamp")
    stamp = datetime.fromisoformat(value[:-1] + "+00:00")
    if stamp.tzinfo is None:
        raise ValueError("source timestamp has no timezone")
    return stamp


class AdvisoryNotReady(ValueError):
    """A release blocker with a fixed message safe to show to operators."""


def release_readiness(reply, binding, *, now=None):
    reply = _object(reply)
    baseline = _object(reply.get("baseline"))
    if type(reply.get("schema_version")) is not int or reply["schema_version"] != 1:
        raise ValueError("invalid advisory status schema")
    if baseline.get("archive_verified") is not True:
        raise AdvisoryNotReady("publisher archive verification is pending")
    if baseline.get("caught_up") is not True or _integer(baseline.get("imported")) == 0:
        raise AdvisoryNotReady("publisher archive import or catch-up is incomplete")
    feeds = reply.get("feeds")
    if not isinstance(feeds, list) or not 1 <= len(feeds) <= 16 or any(type(feed) is not dict for feed in feeds):
        raise ValueError("invalid source status")
    names = [feed.get("source") for feed in feeds]
    if any(not isinstance(name, str) for name in names) or len(names) != len(set(names)) or names.count("cve") != 1:
        raise ValueError("ambiguous CVE source")
    cve = next(feed for feed in feeds if feed["source"] == "cve")
    if cve.get("baseline_digest") != binding["digest"]:
        raise AdvisoryNotReady("CVE delta points to a different publisher archive")
    if (reply.get("bootstrap_complete") is not True or cve.get("complete") is not True
            or cve.get("fresh") is not True or type(cve.get("bootstrap_complete")) is not int
            or cve["bootstrap_complete"] != 1 or cve.get("error") is not None):
        raise AdvisoryNotReady("CVE delta feed is incomplete or stale")
    observed = now or datetime.now(timezone.utc)
    checked = _timestamp(cve.get("checked_at"))
    if not -60 <= (observed - checked).total_seconds() <= 30 * 60:
        raise AdvisoryNotReady("CVE delta status is stale or future-dated")
    cursor = cve.get("cursor")
    if not isinstance(cursor, str) or len(cursor) > 512:
        raise ValueError("CVE delta cursor unavailable")
    cursor = _json(cursor.encode())
    if set(cursor) != {"event", "offset"} or _timestamp(cursor["event"]) > observed or type(cursor["offset"]) is not int:
        raise ValueError("invalid CVE delta position")
    _integer(cursor["offset"])
    return {"phase": "release_ready", "imported": baseline["imported"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("warm", "status"))
    parser.add_argument("--max-steps", type=int, default=MAX_PROOF_STEPS)
    args = parser.parse_args()
    try:
        binding = load_binding()
        if args.operation == "warm":
            warm(binding, os.environ.get("GITHUB_TOKEN"), os.environ.get("RUNTIME_REFRESH_SECRET"), max_steps=args.max_steps)
        else:
            print(json.dumps(release_readiness(request_json(STATUS_PATH), binding)))
        return 0
    except urllib.error.HTTPError as error:
        print(f"Advisory {args.operation} refused: HTTP {error.code}", file=sys.stderr)
        error.close()
    except AdvisoryNotReady as error:
        print(f"Advisory release check refused because {error}.", file=sys.stderr)
    except (urllib.error.URLError, TimeoutError, ValueError, UnicodeError, OSError, KeyError, TypeError):
        print(f"Advisory {args.operation} unavailable, incomplete, or bound to a different baseline", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
