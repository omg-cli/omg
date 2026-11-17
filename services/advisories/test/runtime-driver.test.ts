import { expect, test } from "bun:test";
import { fileURLToPath, URL as NodeURL } from "node:url";
import { readFileSync } from "node:fs";
import { parseDocument } from "yaml";

const driver = fileURLToPath(new NodeURL("../../../scripts/refresh-runtime-advisories.py", import.meta.url));
function python(code: string) {
    const result = Bun.spawnSync(["python", "-c", `import importlib.util, sys, json, io, contextlib, urllib.error\nspec = importlib.util.spec_from_file_location("refresh_driver", sys.argv[1])\ndriver = importlib.util.module_from_spec(spec)\nspec.loader.exec_module(driver)\n${code}`, driver]);
    const stderr = result.stderr.toString();
    if (result.exitCode !== 0) throw new Error(`Python driver test failed: ${stderr}`);
    return result.stdout.toString();
}
test("refresh driver sends credentials only to the fixed endpoint and refreshes every approved feed", () => {
    const output = python(`
requests = []
class Reply:
    status = 200
    def __init__(self, runtime): self.runtime = runtime
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def read(self, limit): return json.dumps({"schema_version": 1, "runtime": self.runtime, "refreshed": True, "coverage": "unknown", "sources": [{"complete": True}]}).encode()
class Opener:
    def open(self, request, timeout):
        assert request.full_url == "https://omg-advisories.latham.workers.dev/internal/runtime-refresh"
        assert request.method == "POST"
        assert request.get_header("Authorization") == "Bearer " + "s" * 40
        body = json.loads(request.data)
        assert set(body) == {"runtime", "github_token"}
        assert body["github_token"] == "ghs_" + "a" * 36
        requests.append(body["runtime"])
        return Reply(body["runtime"])
assert driver.refresh_all("ghs_" + "a" * 36, "s" * 40, Opener()) == 0
assert requests == ["python", "rust", "ruby", "java", "bun", "deno", "zig", "erlang", "php", "swift"], requests
print("fixed origin verified")
`);
    expect(output).toContain("fixed origin verified");
});
test("refresh driver rejects redirects, incomplete refreshes and invalid credentials without printing tokens", () => {
    const output = python(`
secret = "s" * 40
token = "ghs_" + "a" * 36
class Redirect:
    def open(self, request, timeout): raise urllib.error.HTTPError(request.full_url, 307, token + secret, {"Location": "https://attacker.invalid/"}, None)
buffer = io.StringIO()
with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
    assert driver.refresh_all(token, secret, Redirect()) == 1
assert token not in buffer.getvalue() and secret not in buffer.getvalue()
assert driver.refresh_all("ghp_personal_token", secret, Redirect()) == 2
assert driver.refresh_all(token, "short", Redirect()) == 2
print("secrets and redirects verified")
`);
    expect(output).toContain("secrets and redirects verified");
});
test("refresh driver rejects incomplete, mismatched and oversized responses and installs its no-redirect handler", () => {
    const output = python(`
assert any(isinstance(handler, driver.NoRedirect) for handler in driver.secure_opener().handlers)
assert driver.NoRedirect().redirect_request(None, None, 307, "redirect", {}, "https://attacker.invalid") is None
class Reply:
    status = 200
    def __init__(self, raw): self.raw = raw
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def read(self, limit): return self.raw[:limit]
class Opener:
    def __init__(self, raw): self.raw = raw
    def open(self, request, timeout): return Reply(self.raw)
for raw in [b'{"schema_version":1,"runtime":"bun","refreshed":false,"coverage":"unknown","sources":[]}', b'{"schema_version":1,"runtime":"wrong","refreshed":true}', b'x' * (driver.MAX_RESPONSE_BYTES + 1)]:
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        assert driver.refresh_all("ghs_" + "a" * 36, "s" * 40, Opener(raw)) == 1
print("response bounds verified")
`);
    expect(output).toContain("response bounds verified");
});
test("refresh workflow has read-only permissions, pinned checkout and trusted-main triggers", () => {
    const source = readFileSync(new NodeURL("../../../.github/workflows/advisory-refresh.yml", import.meta.url), "utf8");
    const document = parseDocument(source); expect(document.errors).toEqual([]);
    const workflow: unknown = document.toJS();
    expect(workflow).toMatchObject({ permissions: { contents: "read" }, on: { push: { branches: ["main"] }, schedule: [{ cron: "7,37 * * * *" }], workflow_dispatch: null }, jobs: { refresh: { if: "github.ref == 'refs/heads/main'", steps: [{ uses: "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", with: { "persist-credentials": false } }, { env: { GITHUB_TOKEN: "${{ github.token }}", RUNTIME_REFRESH_SECRET: "${{ secrets.RUNTIME_REFRESH_SECRET }}" }, run: "python3 scripts/refresh-runtime-advisories.py" }] } } });
    expect(source).not.toContain("pull_request"); expect(source).not.toContain("INGEST_TOKEN");
});
