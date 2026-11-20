"""Refresh fixed vendor advisory caches using a short-lived Actions job token."""

import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request

ENDPOINT = "https://omg-advisories.latham.workers.dev/internal/runtime-refresh"
RUNTIMES = ("python", "rust", "ruby", "java", "bun", "deno", "zig", "erlang", "php", "swift")
MAX_RESPONSE_BYTES = 256 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def secure_opener():
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        NoRedirect(),
    )


def refresh_all(github_token, refresh_secret, opener=None):
    if not re.fullmatch(r"ghs_[A-Za-z0-9._-]{20,2044}", github_token or "") or not re.fullmatch(
        r"[A-Za-z0-9_-]{32,256}", refresh_secret or ""
    ):
        print("Runtime refresh credentials are missing or invalid", file=sys.stderr)
        return 2
    opener = opener if opener is not None else secure_opener()
    failures = 0
    for runtime in RUNTIMES:
        request = urllib.request.Request(
            ENDPOINT,
            data=json.dumps({"runtime": runtime, "github_token": github_token}).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {refresh_secret}",
                "Content-Type": "application/json",
                "User-Agent": "omg-runtime-feed-refresh/1.0",
            },
            method="POST",
        )
        try:
            with opener.open(request, timeout=40) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                if response.status != 200 or len(raw) > MAX_RESPONSE_BYTES:
                    raise ValueError("invalid refresh response")
                report = json.loads(raw.decode("utf-8"))
            if not isinstance(report, dict) or report.get("schema_version") != 1 or report.get("runtime") != runtime:
                raise ValueError("refresh identity mismatch")
            sources = report.get("sources")
            if report.get("refreshed") is not True or report.get("coverage") not in ("assessed", "partial", "unknown") or not isinstance(sources, list) or not sources or not all(
                isinstance(source, dict) and source.get("complete") is True for source in sources
            ):
                raise ValueError("incomplete refresh")
            print(f"{runtime}: refreshed {len(sources)} sources; coverage={report['coverage']}")
        except urllib.error.HTTPError as error:
            failures += 1
            print(f"{runtime}: refresh HTTP {error.code}", file=sys.stderr)
            error.close()
        except (urllib.error.URLError, TimeoutError, ValueError, UnicodeError, OSError):
            failures += 1
            print(f"{runtime}: refresh unavailable or incomplete", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(refresh_all(os.environ.get("GITHUB_TOKEN"), os.environ.get("RUNTIME_REFRESH_SECRET")))
