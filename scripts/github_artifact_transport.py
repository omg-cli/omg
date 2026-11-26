"""Bounded GitHub Actions metadata and artifact responses."""
import json
import re
import subprocess
import sys
import tempfile
import time

MAX_HTTP_HEADERS = 64 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate provenance key')
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError('nonfinite provenance number: ' + value)


def api(path, limit=1024 * 1024, *, include_status=False, timeout=90):
    command = ['gh', 'api', path]
    if include_status:
        command.append('--include')
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as diagnostic:
        try:
            subprocess.run(command, stdout=output, stderr=diagnostic, check=True, timeout=timeout)
        except subprocess.CalledProcessError as error:
            diagnostic.seek(0)
            error.stderr = diagnostic.read(4097)
            if error.stderr:
                print(error.stderr[:4096].decode(errors='replace').rstrip(), file=sys.stderr)
            if include_status:
                require(output.tell() <= limit, 'GitHub response exceeds limit')
                output.seek(0)
                error.output = output.read(limit + 1)
            raise
        require(output.tell() <= limit, 'GitHub response exceeds limit')
        output.seek(0)
        return output.read(limit + 1)


def http_response(data, body_limit):
    parts = re.split(rb'\r?\n\r?\n', data, maxsplit=1)
    require(len(parts) == 2 and len(parts[0]) <= MAX_HTTP_HEADERS, 'invalid GitHub response headers')
    headers, body = parts
    status_line, *fields = headers.splitlines()
    status = re.fullmatch(rb'HTTP/(?:1\.[01]|2(?:\.0)?|3(?:\.0)?) ([1-5][0-9]{2})(?: [^\r\n]*)?', status_line)
    require(status is not None and all(b':' in field for field in fields), 'invalid GitHub response headers')
    require(len(body) <= body_limit, 'GitHub response exceeds limit')
    retry_after = any(field.split(b':', 1)[0].lower() == b'retry-after' for field in fields)
    return int(status[1]), body, retry_after


def request_body(path, body_limit, timeout, kind):
    # Each retry starts a fresh request and cannot reuse a partial response.
    deadline = time.monotonic() + timeout
    for attempt in range(3):
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'GitHub ' + kind + ' request deadline exhausted')
        try:
            data = api(path, body_limit + MAX_HTTP_HEADERS, include_status=True, timeout=min(remaining, 90))
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as error:
            if isinstance(error, subprocess.CalledProcessError):
                status, retry_after = None, False
                if error.output:
                    if not error.output.startswith(b'HTTP/'):
                        raise
                    status, _, retry_after = http_response(error.output, body_limit)
                incomplete_metadata = (
                    kind == 'metadata' and error.returncode == 1
                    and (error.stderr or b'').strip() == b'unexpected end of JSON input'
                    and (status is None or 200 <= status < 300)
                )
                # Leave rate limits and server-directed delays as explicit failures.
                if retry_after or (status not in (502, 503, 504) and not incomplete_metadata):
                    raise
            delay = 2 ** attempt
            if attempt == 2 or deadline - time.monotonic() <= delay:
                raise
            time.sleep(delay)
        else:
            status, body, _ = http_response(data, body_limit)
            require(200 <= status < 300, 'unsuccessful GitHub ' + kind + ' response')
            return body


def api_json(path):
    return json.loads(request_body(path, 1024 * 1024, 90, 'metadata'),
                      object_pairs_hook=unique_object, parse_constant=reject_constant)
