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

test("source context anchors return at most eighty exact lines around the reported location", async () => {
  const lines = Array.from({length: 1000}, (_, index) => `line ${index + 1}`);
  const tools = sourceReviewTools({...input, sourceFiles: [{...input.sourceFiles[0], content: lines.join("\n")}]});
  expect(await tools.readSource.execute({path: "src/value.mjs", line: 268})).toEqual({
    path: "src/value.mjs", blobSha: "b".repeat(40), lineStart: 229, lineEnd: 308,
    numberedLines: lines.slice(228,308).map((text, index) => ({line: 229 + index, text})),
  });
  const last = await tools.readSource.execute({path: "src/value.mjs", line: 1000});
  expect(last.lineStart).toBe(921);
  expect(last.lineEnd).toBe(1000);
  expect(last.numberedLines).toHaveLength(80);
  await expect(tools.readSource.execute({path: "src/value.mjs", line: 1001})).rejects.toThrow();
});

test("source context refuses an oversized line without a successful-read receipt", async () => {
  let reads = 0;
  const tools = sourceReviewTools({...input, sourceFiles: [{...input.sourceFiles[0], content: "x".repeat(12001)}]}, () => {reads++;});
  await expect(tools.readSource.execute({path: "src/value.mjs", line: 1})).rejects.toThrow("Source excerpt too large");
  expect(reads).toBe(0);
});

test("source audit metadata reports audited paths and an empty real diff", async () => {
  const audit = sourceReviewInputSchema.parse({
    ...input, changedPaths: [], diff: "", auditPaths: ["src/value.mjs"],
  });
  const tools = sourceReviewTools(audit);
  expect(await tools.listChangedFiles.execute({})).toMatchObject({
    changedPaths: [], auditPaths: ["src/value.mjs"],
  });
  expect((await tools.readDiff.execute({ offset: 0, limit: 10 })).content).toBe("");
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
    await tools.readSource.execute({ path: "src/value.mjs", line: 2 }),
  ).toEqual({
    path: "src/value.mjs",
    blobSha: "b".repeat(40),
    lineStart: 1,
    lineEnd: 3,
    numberedLines: [{line: 1, text: "first"}, {line: 2, text: "second"}, {line: 3, text: ""}],
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
    tools.readSource.execute({ path: "../secret", line: 1 }),
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
    ({path}) => {
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
  await tools.readSource.execute({ path: "src/value.mjs", line: 1 });
  expect(readPaths).toEqual(["src/value.mjs"]);
  expect(readDiff).toBe(false);
  await tools.readDiff.execute({ offset: 0, limit: 6 });
  expect(readDiff).toBe(true);
});

test("failure report receipt records only successful supplied evidence reads", async () => {
  const reads: number[] = [];
  const tools = sourceReviewTools(input, () => {}, () => {}, index => reads.push(index));
  await tools.listChangedFiles.execute({});
  await expect(tools.readCiFailure.execute({index: 1})).rejects.toThrow("Unknown CI failure");
  expect(reads).toEqual([]);
  expect(await tools.readCiFailure.execute({index: 0})).toEqual(input.ciFailures[0]);
  expect(reads).toEqual([0]);
});
