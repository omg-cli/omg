import { expect, test } from "bun:test";
import { fetchCi } from "../src/http";
import { receiptKey, requestKey, runIdentity, parseStart } from "../src/contract";
import { createHash } from "node:crypto";
import { planIdentity } from "../runner/plan.mjs";

test("authenticated health exposes the exact runtime plan without starting a workflow", async () => {
  const state = fixture();
  const response = await state.send("/health", undefined);
  expect(response.status).toBe(200);
  expect(await response.json()).toEqual({
    ok: true, engine: "@cloudflare/ci@0.2.0",
    planSha256: createHash("sha256").update(planIdentity).digest("hex"),
  });
  expect((await state.send("/health", undefined, "wrong-token")).status).toBe(401);
  expect(state.creations).toBe(0);
});

const input = parseStart({
  repository: "omg-cli/omg",
  sha: "a".repeat(40),
  ref: "refs/heads/main",
  runId: "123",
  attempt: "1",
});

const id = runIdentity(input);

test("authenticated verification evidence remains readable after a failed workflow", async () => {
  const state = fixture();
  await state.send();
  state.status = "errored";

  const contents = new Map([
    ["logs/regression-red-green.stdout", "trusted verifier stdout"],
    ["logs/regression-red-green.stderr", "trusted verifier stderr"],
    ["reports/regression-baseline.json", '<testsuites name="baseline"/>'],
    ["reports/regression-patched.json", '<testsuites name="patched"/>'],
    ["reports/test-audit-oldIntact.json", '{"phase":"oldIntact"}'],
    ["reports/test-audit-oldFault.json", '{"phase":"oldFault"}'],
    ["reports/test-audit-strongerFault.json", '{"phase":"strongerFault"}'],
    ["reports/test-audit-strongerIntact.json", '{"phase":"strongerIntact"}'],
    ["logs/test-audit-four-state.stdout", "trusted four-state stdout"],
    ["logs/test-audit-four-state.stderr", "trusted four-state stderr"],
  ]);

  for (const [suffix, content] of contents) {
    const [kind, name] = suffix.split("/");
    state.objects.set(`${kind}/${id}/${name}`, content);
    const response = await state.send(`/runs/${id}/${suffix}`, undefined);
    expect(response.status).toBe(200);
    expect(await response.text()).toBe(content);
    expect((await state.send(`/runs/${id}/${suffix}`, undefined, "wrong-token")).status).toBe(401);
  }

  expect((await state.send(`/runs/${id}/reports/regression-unlisted.xml`, undefined)).status).toBe(
    404,
  );
});

function fixture() {
  const objects = new Map<string, string>();
  let exists = false;
  let creations = 0;
  let status = "running";
  let outage = false;
  const tokens: { repo: string; scope: string; ttl: number }[] = [];

  const instance = {
    status: async () => {
      if (outage) throw new Error("private provider diagnostics");

      return { status };
    },
  };

  const env = {
    ARTIFACTS: {
      get: async (repo: string) => ({
        createToken: async (scope: string, ttl: number) => {
          tokens.push({ repo, scope, ttl });

          return {
            plaintext: "fixture-artifact-token",
            id: "fixture-token-id",
            expiresAt: "2026-10-20T18:00:00Z",
          };
        },
      }),
    },
    CI_API_TOKEN: "fixture-owner-token",
    BACKUP_BUCKET: {
      get: async (key: string) => {
        const value = objects.get(key);

        return value === undefined ? null : { text: async () => value, body: value };
      },
      put: async (key: string, value: string, options?: { onlyIf?: unknown }) => {
        if (options?.onlyIf && objects.has(key)) return null;
        objects.set(key, value);

        return {};
      },
    },
    CI_WORKFLOW: {
      get: async () => {
        if (outage) throw new Error("private provider diagnostics");

        if (!exists) throw new Error("instance does not exist");

        return instance;
      },
      create: async () => {
        if (outage) throw new Error("private provider diagnostics");

        if (exists) throw new Error("instance already exists");
        exists = true;
        creations++;

        return instance;
      },
    },
  };

  const send = (path = "/runs", ...args: [body?: string, token?: string]) => {
    const body = args.length ? args[0] : JSON.stringify(input);
    const token = args[1] ?? "fixture-owner-token";

    return fetchCi(
      new Request(`https://fixture.test${path}`, {
        method: body === undefined ? "GET" : "POST",
        headers: { Authorization: `Bearer ${token}` },
        body,
      }),
      env,
    );
  };

  return {
    tokens,
    env,
    objects,
    send,
    get creations() {
      return creations;
    },
    set status(value: string) {
      status = value;
    },
    set outage(value: boolean) {
      outage = value;
    },
  };
}

test("audit evidence routes preserve the purpose-bound run suffix and restrict named objects", async () => {
  const f = fixture();
  const auditId = `${id}-ta-${"b".repeat(16)}`;
  f.objects.set(requestKey(auditId), JSON.stringify(input));
  f.objects.set(`reports/${auditId}/test-audit-oldIntact.json`, '{"phase":"oldIntact"}');
  const response = await f.send(`/runs/${auditId}/reports/test-audit-oldIntact.json`, undefined);
  expect(response.status).toBe(200);
  expect(await response.json()).toEqual({ phase: "oldIntact" });
  expect((await f.send(`/runs/${auditId}/reports/test-audit-unlisted.json`, undefined)).status).toBe(404);
  expect((await f.send(`/runs/${auditId}/reports/test-audit-oldIntact.json`, undefined, "wrong")).status).toBe(401);
});

test("only test audits may carry a full source envelope above 64 KiB", async () => {
  const f = fixture();
  const original = `${"// retained source context\n".repeat(1500)}#[test]\nfn value() {\n assert!(true);\n}\n`;
  const stronger = original.replace(" assert!(true);", " assert_eq!(1, 1);\n assert!(true);");
  const hash = (value: string) => createHash("sha256").update(value).digest("hex");
  const request = { ...input, testAudit: { verifierRevision: "c".repeat(40), proposal: {
    purpose: "existing-test-strengthening", repository: "omg-cli/omg", branch: "main", baseSha: input.sha,
    test: { path: "tests/value.rs", testName: "value", originalBlobSha: createHash("sha1").update(`blob ${Buffer.byteLength(original)}\0${original}`).digest("hex"),
      originalContent: original, newContent: stronger, sha256: hash(stronger), assertionLine: 1503 },
    fault: { path: "src/value.rs", originalBlobSha: "d".repeat(40), oldContentQuote: "2", newContent: "pub const VALUE:u32=1;", sha256: hash("pub const VALUE:u32=1;") },
  } } };
  expect(Buffer.byteLength(JSON.stringify(request))).toBeGreaterThan(65536);
  expect((await f.send("/runs", JSON.stringify(request))).status).toBe(202);
  expect(f.creations).toBe(1);
  expect((await f.send("/runs", JSON.stringify(input) + " ".repeat(65536))).status).toBe(413);
  expect((await f.send("/runs", JSON.stringify(request) + " ".repeat(1024 * 1024))).status).toBe(413);
});

test("a missing get() instance creates the first run instead of escaping as HTTP 500", async () => {
  const f = fixture();
  const response = await f.send().catch(() => new Response(null, { status: 500 }));
  expect(response.status).toBe(202);
  expect(f.creations).toBe(1);
  expect(await response.json()).toMatchObject({ id });
});

test("source token is authenticated, fixed-repository write-only with five minute lifetime", async () => {
  const f = fixture();
  expect((await f.send("/source-token", "{}", "wrong")).status).toBe(401);
  expect(f.tokens).toHaveLength(0);
  const response = await f.send("/source-token", "{}");
  expect(response.status).toBe(200);
  expect(response.headers.get("Cache-Control")).toBe("no-store");
  expect(f.tokens).toEqual([{ repo: "omg", scope: "write", ttl: 300 }]);
  expect(await response.json()).toMatchObject({ token: "fixture-artifact-token" });
});

test("source token forbids scope/repository selection and oversized body", async () => {
  const f = fixture();
  expect((await f.send("/source-token", '{"repo":"other","scope":"read"}')).status).toBe(400);
  expect((await f.send("/source-token", " ".repeat(2049))).status).toBe(413);
  expect(f.tokens).toHaveLength(0);
  expect((await f.send("/source-token", "")).status).toBe(200);
});

test("simultaneous duplicate starts and later replay create exactly one instance", async () => {
  const f = fixture();
  const responses = await Promise.all([f.send(), f.send(), f.send()]);
  expect(responses.map((r) => r.status)).toEqual([202, 202, 202]);
  expect((await f.send()).status).toBe(202);
  expect(f.creations).toBe(1);
});

test("a persisted request without an instance recovers after interruption", async () => {
  const f = fixture();
  f.objects.set(requestKey(id), JSON.stringify(input));
  expect((await f.send()).status).toBe(202);
  expect(f.creations).toBe(1);
});

test("same identity with another branch fails before workflow creation", async () => {
  const f = fixture();
  f.objects.set(requestKey(id), JSON.stringify({ ...input, ref: "refs/heads/prerelease" }));
  expect((await f.send()).status).toBe(409);
  expect(f.creations).toBe(0);
});

test("provider failure is sanitized unavailable, never accepted or treated as missing", async () => {
  const f = fixture();
  f.outage = true;
  const response = await f.send();
  expect(response.status).toBe(503);
  expect(await response.text()).not.toContain("private provider");
  expect(f.creations).toBe(0);
});

test("unauthorized requests cannot create requests or read evidence", async () => {
  const f = fixture();
  expect((await f.send("/runs", JSON.stringify(input), "wrong")).status).toBe(401);
  expect((await f.send(`/runs/${id}/receipt`, undefined, "wrong")).status).toBe(401);
  expect(f.objects.size).toBe(0);
});

test("oversized streamed input and invalid repository are rejected before persistence", async () => {
  const f = fixture();
  expect((await f.send("/runs", " ".repeat(65537))).status).toBe(413);
  expect(
    (await f.send("/runs", JSON.stringify({ ...input, repository: "other/repo" }))).status,
  ).toBe(400);
  expect(f.objects.size).toBe(0);
});

test("receipts require terminal success and existing evidence", async () => {
  const f = fixture();
  await f.send();
  f.objects.set(receiptKey(input), '{"proof":"fixture"}');
  expect((await f.send(`/runs/${id}/receipt`, undefined)).status).toBe(202);
  f.status = "errored";
  expect((await f.send(`/runs/${id}/receipt`, undefined)).status).toBe(422);
  f.status = "complete";
  expect((await f.send(`/runs/${id}/receipt`, undefined)).status).toBe(200);
  f.objects.delete(receiptKey(input));
  expect((await f.send(`/runs/${id}/receipt`, undefined)).status).toBe(502);
});

test("terminal failure evidence is readable without admitting a successful receipt", async () => {
  const f = fixture();
  await f.send();

  const failed = {
    id,
    ...input,
    conclusion: "failure",
    checks: [{ name: "source-format", exitCode: 0 }],
  };

  f.objects.set(receiptKey(input), JSON.stringify(failed));
  expect((await f.send(`/runs/${id}/evidence`, undefined)).status).toBe(202);
  f.status = "errored";
  const response = await f.send(`/runs/${id}/evidence`, undefined);
  expect(response.status).toBe(200);
  expect(await response.json()).toEqual(failed);
  expect((await f.send(`/runs/${id}/receipt`, undefined)).status).toBe(422);
  expect((await f.send(`/runs/${id}/evidence`, undefined, "wrong")).status).toBe(401);
});

test("known request with unavailable status returns sanitized 503", async () => {
  const f = fixture();
  await f.send();
  f.outage = true;
  const response = await f.send(`/runs/${id}`, undefined);
  expect(response.status).toBe(503);
  expect(await response.text()).not.toContain("private provider");
});

test("unknown evidence key cannot read unrelated R2 objects", async () => {
  const f = fixture();
  await f.send();
  f.objects.set(`logs/${id}/secret`, "private fixture");
  expect((await f.send(`/runs/${id}/logs/secret`, undefined)).status).toBe(404);
});
