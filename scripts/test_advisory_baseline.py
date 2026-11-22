import importlib.util
import copy
from contextlib import redirect_stderr
from datetime import datetime, timezone
import http.server
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest import mock
import urllib.error
import urllib.request

from test_ci_gates import job_block
from test_release_workflow_boundaries import BASH, step_script

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("advisory_baseline", ROOT / "scripts/advisory-baseline.py")
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)
NOW = datetime(2026, 11, 17, 12, tzinfo=timezone.utc)
JOB_TOKEN = "ghs_12345_fixture.header-" + "0" * 475 + ".signature_fixture"
SECRET = "fixture_refresh_secret_" + "x" * 32


class Response:
    def __init__(self, value, path=DRIVER.PROOF_PATH, status=200, raw=None, url=None):
        self.raw = json.dumps(value).encode() if raw is None else raw
        self.status, self.url = status, url or DRIVER.ORIGIN + path

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def geturl(self):
        return self.url

    def read(self, count):
        return self.raw[:count]


class Opener:
    def __init__(self, responses):
        self.responses, self.calls = list(responses), []

    def open(self, request, timeout):
        self.calls.append((request, timeout))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def progress(binding, **changes):
    return dict(schema_version=1, phase="traversing", expected_count=42, verified_count=0,
                pending_trees=3, archive_verified=False, commit_sha="a" * 40,
                **{key: binding[key] for key in ("digest", "release_tag", "asset")}) | changes


def status(binding):
    return {"schema_version": 1, "baseline": {"imported": 42, "caught_up": True, "archive_verified": True},
            "bootstrap_complete": True, "feeds": [{"source": "cve", "complete": True,
                "fresh": True, "bootstrap_complete": 1, "error": None,
                "baseline_digest": binding["digest"], "checked_at": "2026-11-17T11:59:00.000Z",
                "cursor": json.dumps({"event": "2026-11-17T11:58:00.000Z", "offset": 0})}]}


class AdvisoryBaselineDriverTests(unittest.TestCase):
    def setUp(self):
        self.binding = DRIVER.load_binding()

    def test_binding_rejects_stale_checkpoint_and_external_endpoint(self):
        saved = json.loads(DRIVER.BINDING_FILE.read_text(encoding="utf-8"))
        for change in ("endpoint", "digest", "checkpoint", "numeric-instance", "missing-finish"):
            broken = copy.deepcopy(saved)
            if change == "endpoint":
                broken["baseline"]["endpoint"] = "https://untrusted.invalid"
            elif change == "digest":
                broken["baseline"]["digest"] = "0" * 64
            elif change == "numeric-instance":
                broken["baseline"]["instance_id"] = int("1" * 32)
            elif change == "missing-finish":
                del broken["finished_at"]
            else:
                broken.update(accepted=42, next_entry=42, exhausted=True, finished_at="2026-11-17T00:00:00.000Z")
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "binding.json"
                path.write_text(json.dumps(broken), encoding="utf-8")
                with self.assertRaises(ValueError):
                    DRIVER.load_binding(path)

    def test_warming_is_serial_bounded_and_stops_for_real_import(self):
        opener = Opener([Response(progress(self.binding)), Response(progress(self.binding, phase="awaiting_import", pending_trees=0))])
        output = []
        result = DRIVER.warm(self.binding, JOB_TOKEN, SECRET, opener=opener, emit=output.append)
        self.assertEqual(result["phase"], "awaiting_import")
        self.assertEqual(len(opener.calls), 2)
        for request, timeout in opener.calls:
            self.assertEqual(request.full_url, DRIVER.ORIGIN + DRIVER.PROOF_PATH)
            self.assertEqual(request.method, "POST")
            self.assertEqual(timeout, 40)
            self.assertEqual(request.get_header("Authorization"), "Bearer " + SECRET)
            body = json.loads(request.data)
            self.assertEqual(body, dict(self.binding, github_token=JOB_TOKEN))
            self.assertNotIn("accepted", body)
        for line in output:
            row = json.loads(line)
            self.assertEqual(set(row), {"phase", "expected_count", "verified_count", "pending_trees", "step"})
            self.assertNotIn(JOB_TOKEN, line)
            self.assertNotIn(SECRET, line)

    def test_budget_exhaustion_never_claims_verified(self):
        opener = Opener([Response(progress(self.binding)) for _ in range(20)])
        result = DRIVER.warm(self.binding, JOB_TOKEN, SECRET, max_steps=20, opener=opener, emit=lambda _line: None)
        self.assertEqual(result["phase"], "traversing")
        self.assertEqual(len(opener.calls), 20)

    def test_one_run_can_finish_the_full_publisher_traversal_and_reconciliation(self):
        replies = [Response(progress(self.binding)) for _ in range(185)]
        replies.append(Response(progress(self.binding, phase="verified", archive_verified=True,
                                         expected_count=424_926, verified_count=424_926, pending_trees=0)))
        opener = Opener(replies)
        result = DRIVER.warm(self.binding, JOB_TOKEN, SECRET, max_steps=256, opener=opener, emit=lambda _line: None)
        self.assertEqual(result["phase"], "verified")
        self.assertEqual(len(opener.calls), 186)

    def test_cron_lease_contention_retries_five_attempts_with_bounded_backoff(self):
        errors = [urllib.error.HTTPError(DRIVER.ORIGIN + DRIVER.PROOF_PATH, 409, "busy", {}, None) for _ in range(4)]
        opener = Opener(errors + [Response(progress(self.binding, phase="awaiting_catchup", pending_trees=0))])
        delays = []
        result = DRIVER.warm(self.binding, JOB_TOKEN, SECRET, opener=opener, sleep=delays.append, emit=lambda _line: None)
        self.assertEqual(result["phase"], "awaiting_catchup")
        self.assertEqual(delays, [1, 2, 4, 8])
        self.assertEqual(len(opener.calls), 5)
        self.assertTrue(all(error.closed for error in errors))

    def test_lease_retries_are_capped_and_other_http_errors_are_not_retried(self):
        for status_code, expected_calls, expected_delays in ((409, 5, [1, 2, 4, 8]), (403, 1, [])):
            errors = [urllib.error.HTTPError(DRIVER.ORIGIN + DRIVER.PROOF_PATH, status_code, "controlled failure", {}, None) for _ in range(expected_calls)]
            opener, delays = Opener(errors), []
            with self.subTest(status_code=status_code), self.assertRaises(urllib.error.HTTPError) as rejected:
                DRIVER.warm(self.binding, JOB_TOKEN, SECRET, opener=opener, sleep=delays.append, emit=lambda _line: None)
            rejected.exception.close()
            self.assertEqual(len(opener.calls), expected_calls)
            self.assertEqual(delays, expected_delays)

    def test_total_monotonic_deadline_caps_requests_without_claiming_verification(self):
        elapsed = [0.0]
        class TimedOpener(Opener):
            def open(self, request, timeout):
                response = super().open(request, timeout)
                elapsed[0] += min(37, timeout)
                return response
        opener = TimedOpener([Response(progress(self.binding)) for _ in range(256)])
        output = []
        result = DRIVER.warm(self.binding, JOB_TOKEN, SECRET, opener=opener,
                             clock=lambda: elapsed[0], emit=output.append)
        self.assertEqual(elapsed[0], 480)
        self.assertEqual(len(opener.calls), 13)
        self.assertEqual(opener.calls[-1][1], 36)
        self.assertEqual(result["phase"], "traversing")
        self.assertEqual(json.loads(output[-1])["budget_exhausted"], 1)

    def test_deadline_without_server_progress_cannot_fabricate_a_phase(self):
        clock = iter((0, 481))
        opener, output = Opener([]), []
        with self.assertRaises(TimeoutError):
            DRIVER.warm(self.binding, JOB_TOKEN, SECRET, opener=opener,
                        clock=lambda: next(clock), emit=output.append)
        self.assertEqual(opener.calls, [])
        self.assertEqual(output, [])

    def test_personal_token_and_invalid_secret_never_reach_transport(self):
        opener = Opener([])
        for token, secret in (("ghp_" + "fixturefake" + "0" * 25, SECRET), (JOB_TOKEN, "short")):
            with self.subTest(token_kind=token[:4]), self.assertRaises(ValueError):
                DRIVER.warm(self.binding, token, secret, opener=opener)
        self.assertEqual(opener.calls, [])

    def test_stale_or_fabricated_publisher_proofs_cannot_certify(self):
        for fields in (
            {"digest": "0" * 64}, {"asset": "different.zip"}, {"release_tag": "cve_2000-01-01_0000Z"},
            {"commit_sha": "bad"}, {"commit_sha": int("1" * 40)}, {"phase": "verified", "archive_verified": False},
            {"phase": "verified", "archive_verified": True, "expected_count": 0, "verified_count": 0, "pending_trees": 0},
            {"phase": "verified", "archive_verified": True, "verified_count": 41, "pending_trees": 0},
            {"phase": "verified", "archive_verified": True, "verified_count": 42, "pending_trees": 1},
            {"archive_verified": True}, {"expected_count": True},
        ):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                DRIVER.proof_progress(progress(self.binding, **fields), self.binding)
        self.assertEqual(DRIVER.proof_progress(progress(self.binding, phase="verified", archive_verified=True, verified_count=42, pending_trees=0), self.binding)["phase"], "verified")

    def test_fixed_origin_transport_rejects_redirect_oversize_and_credential_echo(self):
        for response in (
            Response({}, status=302), Response({}, url="https://untrusted.invalid/leak"),
            Response({}, raw=b"x" * (DRIVER.MAX_BODY + 1)),
            Response({"echo": JOB_TOKEN}), Response({"echo": SECRET}),
        ):
            opener = Opener([response])
            with self.subTest(response=response.url), self.assertRaises(ValueError):
                DRIVER.request_json(DRIVER.PROOF_PATH, body=dict(self.binding, github_token=JOB_TOKEN), secret=SECRET, opener=opener)
            self.assertEqual(len(opener.calls), 1)
        with self.assertRaises(ValueError):
            DRIVER.request_json("https://untrusted.invalid/leak")

    def test_actual_secure_opener_does_not_follow_redirect_or_environment_proxy(self):
        paths = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                paths.append(self.path)
                self.send_response(302)
                self.send_header("Location", "/credential-trap")
                self.end_headers()
            def log_message(self, *_args):
                return
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with mock.patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:1", "http_proxy": "http://127.0.0.1:1", "NO_PROXY": "", "no_proxy": ""}):
                opener = DRIVER._transport.secure_opener()
                request = urllib.request.Request(f"http://127.0.0.1:{server.server_port}/original", headers={"Authorization": "Bearer " + SECRET})
                with self.assertRaises(urllib.error.HTTPError) as rejected:
                    opener.open(request, timeout=5)
                self.assertEqual(rejected.exception.code, 302)
                rejected.exception.close()
            self.assertEqual(paths, ["/original"])
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)

    def test_readiness_uses_server_certification_and_fresh_delta_not_operator_count(self):
        ready = status(self.binding)
        self.assertEqual(DRIVER.release_readiness(ready, self.binding, now=NOW)["phase"], "release_ready")
        ready["baseline"]["imported"] = 1
        self.assertEqual(DRIVER.release_readiness(ready, self.binding, now=NOW)["imported"], 1)
        for change in ("archive", "bootstrap", "catchup", "count-only", "stale", "future", "binding", "error", "duplicate", "cursor", "flag-type"):
            broken = status(self.binding)
            cve = broken["feeds"][0]
            if change in ("archive", "count-only"):
                broken["baseline"].update(archive_verified=False, imported=999_999)
            elif change == "bootstrap": broken["bootstrap_complete"] = False
            elif change == "catchup": broken["baseline"]["caught_up"] = False
            elif change == "stale": cve["checked_at"] = "2026-11-17T11:29:59.000Z"
            elif change == "future": cve["checked_at"] = "2026-11-17T12:01:01.000Z"
            elif change == "binding": cve["baseline_digest"] = "0" * 64
            elif change == "error": cve["error"] = "partial upstream"
            elif change == "duplicate": broken["feeds"].append(dict(cve))
            elif change == "cursor": cve["cursor"] = "null"
            elif change == "flag-type": cve["complete"] = 1
            with self.subTest(change=change), self.assertRaises(ValueError):
                DRIVER.release_readiness(broken, self.binding, now=NOW)

    def test_public_readiness_request_never_sends_credentials(self):
        opener = Opener([Response(status(self.binding), path=DRIVER.STATUS_PATH)])
        reply = DRIVER.request_json(DRIVER.STATUS_PATH, opener=opener)
        self.assertTrue(reply["bootstrap_complete"])
        request, _timeout = opener.calls[0]
        self.assertEqual(request.get_header("Cache-control"), "no-cache")
        self.assertIsNone(request.get_header("Authorization"))
        self.assertIsNone(request.data)

    def test_status_names_archive_and_delta_blockers_without_printing_provider_text(self):
        for archive_verified, reason in (
            (False, "publisher archive verification is pending"),
            (True, "CVE delta feed is incomplete or stale"),
        ):
            reply = status(self.binding)
            reply["baseline"]["archive_verified"] = archive_verified
            reply["bootstrap_complete"] = False
            reply["feeds"][0].update(complete=False, bootstrap_complete=0, error=SECRET)
            stderr = io.StringIO()
            with self.subTest(archive_verified=archive_verified), \
                    mock.patch.object(DRIVER.sys, "argv", ["advisory-baseline.py", "status"]), \
                    mock.patch.object(DRIVER, "request_json", return_value=reply), \
                    redirect_stderr(stderr):
                self.assertEqual(DRIVER.main(), 1)
                self.assertIn(reason, stderr.getvalue())
                self.assertNotIn(SECRET, stderr.getvalue())


class AdvisoryReleaseBoundaryTests(unittest.TestCase):
    def test_warming_stays_on_trusted_main_with_read_only_job_token(self):
        workflow = (ROOT / ".github/workflows/advisory-refresh.yml").read_text(encoding="utf-8")
        self.assertIn("contents: read", workflow)
        self.assertNotIn("pull_request", workflow)
        job = job_block(workflow, "baseline-proof")
        self.assertIn("if: github.ref == 'refs/heads/main'", job)
        self.assertIn("GITHUB_TOKEN: ${{ github.token }}", job)
        self.assertIn("RUNTIME_REFRESH_SECRET: ${{ secrets.RUNTIME_REFRESH_SECRET }}", job)
        self.assertIn("persist-credentials: false", job)
        self.assertIn("warm --max-steps 256", job)
        self.assertIn("timeout-minutes: 10", job)

    def test_each_publication_boundary_rechecks_status(self):
        release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        create = job_block(release, "release")
        self.assertLess(create.index("python3 scripts/advisory-baseline.py status"), create.index("- name: Publish GitHub Release"))
        sync = job_block(release, "sync-r2")
        self.assertLess(sync.index("python3 scripts/advisory-baseline.py status"), sync.index("- name: Upload release artifacts to R2"))
        marker = step_script(sync, "Upload latest-version marker")
        self.assertLess(marker.index("python3 scripts/advisory-baseline.py status"), marker.index('r2 object put "omg-releases/latest-version"'))

    def test_pending_advisory_baseline_prevents_immutable_tag_creation(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        script = step_script(job_block(workflow, "release-tag"),
                             "Tag Cargo.toml version when all platform builds succeeded")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Cargo.toml").write_text('version = "0.1.225"\n', encoding="utf-8", newline="\n")
            (root / "bin").mkdir()
            (root / "scripts").mkdir()
            fixtures = {
                "bin/git": '#!/bin/sh\ncase "$1" in ls-remote) test -f tag-created;; tag) touch tag-created;; push) touch pushed;; esac\n',
                "bin/gh": "#!/bin/sh\nexit 0\n",
                "bin/python3": "#!/bin/sh\ntouch readiness-called\nexit 1\n",
                "scripts/require-workflow-success.sh": "#!/bin/sh\nexit 0\n",
            }
            for name, text in fixtures.items():
                path = root / name
                path.write_text(text, encoding="utf-8", newline="\n")
                path.chmod(0o700)
            environment = dict(os.environ, PATH=str(root / "bin") + os.pathsep + os.environ["PATH"],
                               GITHUB_SHA="a" * 40, GITHUB_REF="refs/heads/main",
                               GITHUB_EVENT_NAME="workflow_dispatch", RELEASE_CANDIDATE="v0.1.225@" + "a" * 40,
                               GITHUB_STEP_SUMMARY=str(root / "summary"),
                               LINUX_MATRIX="success", SANDBOX_CANCELLATION="success",
                               FEATURE_INTERSECTIONS="success", MACOS="success", UBUNTU="success")
            result = subprocess.run([BASH, "-e", "-o", "pipefail", "-c", script], cwd=root,
                                    env=environment, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "tag-created").exists(), "pending baseline consumed the release tag")
            self.assertFalse((root / "pushed").exists())
            self.assertTrue((root / "readiness-called").exists())


if __name__ == "__main__":
    unittest.main()
