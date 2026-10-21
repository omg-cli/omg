import { expect, test } from "bun:test";
import { reviewRecords } from "../src/review-records";
import { fetchCi } from "../src/http";

const report = {
  repository: "omg-cli/omg",
  sha: "a".repeat(40),
  branch: "main",
  nested: { z: 2, a: 1 },
  publications: [],
};

const envelope = { repository: report.repository, runId: "123", attempt: "1", report };

function fixture() {
  const records = new Map<string, string>();
  let unavailable = false;

  const bucket = {
    get: async (key: string) => {
      if (unavailable) throw new Error("secret provider diagnostic");
      const value = records.get(key);

      return value === undefined ? null : { text: async () => value, body: value };
    },
    put: async (key: string, value: string, options?: R2PutOptions) => {
      if (unavailable) throw new Error("secret provider diagnostic");

      if (options?.onlyIf && records.has(key)) return null;
      records.set(key, value);

      return {};
    },
  };

  const send = (body?: string, path = "123-1") =>
    reviewRecords(
      new Request(`https://fixture.test/review-records/${path}`, {
        method: body === undefined ? "GET" : "POST",
        body,
      }),
      bucket,
    );

  return {
    bucket,
    records,
    send,
    set unavailable(value: boolean) {
      unavailable = value;
    },
  };
}

test("stores a private review once and returns only the report", async () => {
  const f = fixture();
  const response = await f.send(JSON.stringify(envelope));
  expect(response.status).toBe(200);
  expect(response.headers.get("Cache-Control")).toBe("no-store");
  expect([...f.records.keys()]).toEqual(["reviews/123-1/review.json"]);
  const fetched = await f.send();
  expect(fetched.status).toBe(200);
  expect(await fetched.json()).toEqual(report);
});

test("HTTP routing authenticates before accessing review records", async () => {
  const f = fixture();

  const unavailable = async () => {
    throw new Error("Unrelated binding must not be called");
  };

  const env = {
    CI_API_TOKEN: "fixture-owner",
    BACKUP_BUCKET: f.bucket,
    ARTIFACTS: { get: unavailable },
    CI_WORKFLOW: { get: unavailable, create: unavailable },
  };

  const denied = await fetchCi(
    new Request("https://fixture.test/review-records/123-1", {
      method: "POST",
      body: JSON.stringify(envelope),
    }),
    env,
  );

  expect(denied.status).toBe(401);
  expect(f.records.size).toBe(0);

  const accepted = await fetchCi(
    new Request("https://fixture.test/review-records/123-1", {
      method: "POST",
      headers: { Authorization: "Bearer fixture-owner" },
      body: JSON.stringify(envelope),
    }),
    env,
  );

  expect(accepted.status).toBe(200);
});

test("canonical identical retries and concurrent claims succeed while changed reports conflict", async () => {
  const f = fixture();

  const responses = await Promise.all([
    f.send(JSON.stringify(envelope)),
    f.send(
      JSON.stringify({
        report: { ...report, nested: { a: 1, z: 2 } },
        attempt: "1",
        runId: "123",
        repository: report.repository,
      }),
    ),
  ]);

  expect(responses.map((response) => response.status)).toEqual([200, 200]);
  expect(
    (await f.send(JSON.stringify({ ...envelope, report: { ...report, nested: { z: 3, a: 1 } } })))
      .status,
  ).toBe(409);
  expect(f.records.size).toBe(1);
});

test("rejects route and identity confusion before persistence", async () => {
  const f = fixture();

  for (const body of [
    { ...envelope, extra: true },
    { ...envelope, runId: "124" },
    { ...envelope, report: { ...report, repository: "other/repo" } },
    { ...envelope, report: { ...report, branch: "other" } },
    { ...envelope, report: { ...report, sha: "short" } },
  ])
    expect((await f.send(JSON.stringify(body))).status).toBe(400);
  expect((await f.send(undefined, "123-0")).status).toBe(404);
  expect((await f.send(undefined, "123-1/secret")).status).toBe(404);
  expect(f.records.size).toBe(0);
});

test("streamed body budget and provider errors fail closed without exposing diagnostics", async () => {
  const f = fixture();
  expect((await f.send(" ".repeat(2 * 1024 * 1024 + 1))).status).toBe(413);
  f.unavailable = true;
  const response = await f.send(JSON.stringify(envelope));
  expect(response.status).toBe(503);
  expect(await response.text()).not.toContain("secret provider");
});

test("missing and corrupt stored records cannot become successful reports", async () => {
  const f = fixture();
  expect((await f.send()).status).toBe(404);
  f.records.set("reviews/123-1/review.json", JSON.stringify({ ...envelope, runId: "456" }));
  expect((await f.send()).status).toBe(503);
});
