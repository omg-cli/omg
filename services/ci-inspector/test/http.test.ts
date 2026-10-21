import { expect, test } from "bun:test";
import { handleInspection } from "../src/http";

const snapshot = {
  repository: "omg-cli/omg",
  runId: 1,
  branch: "main",
  sha: "a".repeat(40),
  prompt: "Explain failures.",
  jobs: [
    {
      id: 2,
      name: "Unit",
      status: "completed",
      conclusion: "failure",
      failedSteps: [{ name: "Test", log: "expected 1, received 2" }],
    },
  ],
};

const env = { CI_INSPECTOR_TOKEN: "owner-secret" };

function request(
  payload: Parameters<typeof JSON.stringify>[0] = snapshot,
  token = env.CI_INSPECTOR_TOKEN,
) {
  return new Request("https://worker.example/inspect", {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
}

test("unauthorized input never reaches inference", async () => {
  let attempts = 0;

  const response = await handleInspection(request(snapshot, "wrong"), env, async () => {
    attempts++;

    return { summary: "unsafe" };
  });

  expect(response.status).toBe(401);
  expect(attempts).toBe(0);
});

test("accepts only the fixed repository", async () => {
  let attempts = 0;

  const response = await handleInspection(
    request({ ...snapshot, repository: "other/repo" }),
    env,
    async () => {
      attempts++;

      return { summary: "unsafe" };
    },
  );

  expect(response.status).toBe(400);
  expect(attempts).toBe(0);
});

test("bounds payload and log lengths before inference", async () => {
  let attempts = 0;

  const inspect = async () => {
    attempts++;

    return { summary: "unsafe" };
  };

  expect(
    (await handleInspection(request({ ...snapshot, prompt: "x".repeat(140000) }), env, inspect))
      .status,
  ).toBe(413);
  expect(
    (
      await handleInspection(
        request({
          ...snapshot,
          jobs: [{ ...snapshot.jobs[0], failedSteps: [{ name: "Test", log: "x".repeat(12001) }] }],
        }),
        env,
        inspect,
      )
    ).status,
  ).toBe(400);
  expect(attempts).toBe(0);
});

test("returns accepted snapshot identity and actual inspector result", async () => {
  const response = await handleInspection(request(), env, async (input) => ({
    summary: input.jobs[0]?.failedSteps[0]?.log ?? "",
  }));

  expect(response.status).toBe(200);
  expect(await response.json()).toEqual({
    repository: snapshot.repository,
    runId: 1,
    branch: "main",
    sha: snapshot.sha,
    summary: "expected 1, received 2",
  });
});
