import assert from "node:assert/strict";
import { test } from "bun:test";
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import type { DirectAccessToken, GitLabOAuthTokenResponse } from "gitlab-ai-provider";

const coreRequire = createRequire(import.meta.resolve("@opencode/core/plugin/promise"));
const providerEntry = coreRequire.resolve("gitlab-ai-provider");
const esm: typeof import("gitlab-ai-provider") = await import(pathToFileURL(join(dirname(providerEntry), "index.mjs")).href);
const cjs: typeof import("gitlab-ai-provider") = coreRequire("gitlab-ai-provider");
const token: DirectAccessToken = {
  token: "fixture-direct-token",
  headers: { "X-GitLab-Instance-ID": "123", "x-arbitrary.header": "kept", Authorization: "Bearer fixture" },
};
const oauth: GitLabOAuthTokenResponse = {
  access_token: "fixture-access-token", refresh_token: "fixture-refresh-token", expires_in: 7200, created_at: 1800000000,
};

test("installed GitLab provider resolves the patched Zod runtime", () => {
  assert.equal(createRequire(providerEntry)("zod/package.json").version, "4.6.7");
});

for (const [format, provider] of [["ESM", esm], ["CJS", cjs]] as const) {
  test(`${format} GitLab OAuth response keeps required fields and rejects malformed responses`, () => {
    const parsed: GitLabOAuthTokenResponse = provider.gitlabOAuthTokenResponseSchema.parse({ ...oauth, ignored: true });
    const accessToken: string = parsed.access_token;
    const lifetime: number = parsed.expires_in;
    assert.equal(accessToken, oauth.access_token);
    assert.equal(lifetime, oauth.expires_in);
    assert.deepEqual(parsed, oauth);
    for (const invalid of [null, {}, { ...oauth, access_token: 123 }, { ...oauth, expires_in: "7200" },
      { refresh_token: "fixture", expires_in: 7200, created_at: 1800000000 }])
      assert.equal(provider.gitlabOAuthTokenResponseSchema.safeParse(invalid).success, false);
  });

  test(`${format} GitLab direct access preserves arbitrary headers and rejects malformed tokens`, async () => {
    const client = (payload: unknown) => new provider.GitLabDirectAccessClient({
      instanceUrl: "https://gitlab.example.test", getHeaders: () => ({ Authorization: "Bearer fixture" }),
      directAccessCacheDir: "", fetch: Object.assign(async () => Response.json(payload), { preconnect: fetch.preconnect }),
    });
    const parsed: DirectAccessToken = await client({ ...token, ignored: true }).getDirectAccessToken();
    const header: string | undefined = parsed.headers["x-arbitrary.header"];
    const accessToken: string = parsed.token;
    assert.equal(header, "kept");
    assert.equal(accessToken, token.token);
    assert.deepEqual(parsed, token);
    for (const invalid of [null, {}, { headers: token.headers }, { token: token.token },
      { ...token, token: 123 }, { ...token, headers: { "X-Bad-Header": 123 } }])
      await assert.rejects(client(invalid).getDirectAccessToken());
  });

  test.skipIf(process.platform === "win32")(`${format} GitLab private token cache validates writes and reads`, async () => {
    const directory = await mkdtemp(join(tmpdir(), "omg-gitlab-zod-"));
    let fetches = 0;
    const client = (payload: unknown = token) => new provider.GitLabDirectAccessClient({
      instanceUrl: "https://gitlab.example.test", getHeaders: () => ({ Authorization: "Bearer fixture" }),
      directAccessCacheDir: directory,
      fetch: Object.assign(async () => { fetches++; return Response.json(payload); }, { preconnect: fetch.preconnect }),
    });
    try {
      assert.deepEqual(await client().getDirectAccessToken(), token);
      assert.deepEqual(await client().getDirectAccessToken(), token);
      assert.equal(fetches, 1);
      assert.equal((await stat(directory)).mode & 0o077, 0);
      const entries = (await readdir(directory)).filter((name) => name.endsWith(".json"));
      assert.equal(entries.length, 1);
      const [entryName] = entries;
      assert.ok(entryName);
      const entry = join(directory, entryName);
      assert.equal((await stat(entry)).mode & 0o077, 0);
      const cached = JSON.parse(await readFile(entry, "utf8"));
      assert.deepEqual(cached.value, token);
      await writeFile(entry, JSON.stringify({ ...cached, value: { ...token, headers: { "X-Bad-Header": 123 } } }));
      await assert.rejects(client().getDirectAccessToken());
      assert.equal(fetches, 1);
      await rm(entry);
      await assert.rejects(client({ ...token, token: "" }).getDirectAccessToken());
      await assert.rejects(client({ ...token, headers: { "X-Bad-Header": 123 } }).getDirectAccessToken());
      assert.deepEqual((await readdir(directory)).filter((name) => name.endsWith(".json")), []);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
}
