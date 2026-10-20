import { expect, test } from "bun:test";
import { sourceReviewTools } from "../src/review-tools";
import { sourceReviewInputSchema } from "../src/review-contract";

const input = sourceReviewInputSchema.parse({
  repository: "omg-cli/omg",
  sha: "a".repeat(40),
  branch: "main",
  changedPaths: ["src/value.mjs"],
  diff: "+value",
  sourceFiles: [{ path: "src/value.mjs", blobSha: "b".repeat(40), content: "first\nsecond\n" }],
  ciFailures: [{ job: "Unit", step: "Test", log: "actual assertion" }],
});

test("source review has only bounded supplied-data read tools", async () => {
  let reads = 0;

  const tools = sourceReviewTools(input, () => {
    reads++;
  });

  expect(Object.keys(tools)).toEqual([
    "listChangedFiles",
    "readSource",
    "readDiff",
    "readCiFailure",
  ]);
  expect(
    await tools.readSource.execute({ path: "src/value.mjs", lineStart: 2, lineEnd: 2 }),
  ).toEqual({
    path: "src/value.mjs",
    blobSha: "b".repeat(40),
    lineStart: 2,
    lineEnd: 2,
    content: "second",
  });
  expect(reads).toBe(1);
  expect(await tools.readDiff.execute({ offset: 0, limit: 4 })).toEqual({
    offset: 0,
    content: "+val",
    totalCharacters: 6,
  });
  expect(await tools.readCiFailure.execute({ index: 0 })).toEqual(input.ciFailures[0]);
});

test("source review tool arguments and total calls are bounded at execution", async () => {
  const tools = sourceReviewTools(input);
  expect(
    tools.readSource.execute({ path: "../secret", lineStart: 1, lineEnd: 2 }),
  ).rejects.toThrow();
  expect(tools.readDiff.execute({ offset: 0, limit: 12001 })).rejects.toThrow();

  for (let index = 0; index < 16; index++) await tools.listChangedFiles.execute({});
  expect(tools.listChangedFiles.execute({})).rejects.toThrow("Tool call limit");
});

test("source tools receipt reports only successful actual file and diff reads", async () => {
  const readPaths: string[] = [];
  let readDiff = false;

  const tools = sourceReviewTools(
    input,
    (path) => {
      readPaths.push(path);
    },
    () => {
      readDiff = true;
    },
  );

  await tools.listChangedFiles.execute({});
  expect(readPaths).toEqual([]);
  expect(readDiff).toBe(false);
  await tools.readDiff.execute({ offset: 6, limit: 1 });
  expect(readDiff).toBe(false);
  await tools.readSource.execute({ path: "src/value.mjs", lineStart: 1, lineEnd: 1 });
  expect(readPaths).toEqual(["src/value.mjs"]);
  expect(readDiff).toBe(false);
  await tools.readDiff.execute({ offset: 0, limit: 6 });
  expect(readDiff).toBe(true);
});
