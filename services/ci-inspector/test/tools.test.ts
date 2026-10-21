import { expect, test } from "bun:test";
import { snapshotSchema } from "../src/snapshot";
import { snapshotTools } from "../src/tools";

const snapshot = snapshotSchema.parse({
  repository: "omg-cli/omg",
  runId: 1,
  branch: "prerelease",
  sha: "a".repeat(40),
  prompt: "Explain",
  jobs: [
    {
      id: 2,
      name: "Unit",
      status: "completed",
      conclusion: "failure",
      failedSteps: [{ name: "Test", log: "real failure" }],
    },
  ],
});

test("tools expose only listing and selected snapshot log reads", async () => {
  const tools = snapshotTools(snapshot);
  expect(Object.keys(tools)).toEqual(["listJobs", "readFailedStep"]);
  expect(await tools.listJobs.execute({})).toEqual([
    { id: 2, name: "Unit", status: "completed", conclusion: "failure", failedSteps: ["Test"] },
  ]);
  expect(await tools.readFailedStep.execute({ jobId: 2, step: "Test" })).toEqual({
    jobId: 2,
    step: "Test",
    log: "real failure",
  });
});

test("tool boundary rejects unknown selection and invalid arguments", async () => {
  const tools = snapshotTools(snapshot);
  expect(tools.readFailedStep.execute({ jobId: 999, step: "Test" })).rejects.toThrow(
    "Unknown failed step",
  );
  expect(tools.readFailedStep.execute({ jobId: "2", step: "Test" })).rejects.toThrow();
});

test("tool budget bounds repeated reads", async () => {
  const tools = snapshotTools(snapshot);

  for (let index = 0; index < 12; index++) await tools.listJobs.execute({});
  expect(tools.listJobs.execute({})).rejects.toThrow("Tool call limit");
});
