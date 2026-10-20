import path from "node:path";
import { readFile } from "node:fs/promises";
import { Schema } from "effect";

const repositoryRoot = Schema.String.check(
  Schema.makeFilter(
    (value) =>
      value.length > 0 &&
      !value.includes("\0") &&
      (path.posix.isAbsolute(value) || path.win32.isAbsolute(value)),
  ),
);

const reportCase = Schema.Struct({
  fullName: Schema.String.check(Schema.makeFilter((name) => name.trim().length > 0)),
  status: Schema.Literals(["passed", "failed", "skipped"]),
});

export function compareBrowserReports(release, prerelease, { root } = {}) {
  if (!Schema.is(repositoryRoot)(root)) throw new Error("An absolute repository root is required.");
  const paths = path.posix.isAbsolute(root) ? path.posix : path.win32;

  const reportFile = Schema.Struct({
    name: Schema.String.check(
      Schema.makeFilter((name) => !name.includes("\0") && paths.isAbsolute(name)),
    ),
  });

  function collect(report, lane) {
    if (report?.success !== true) throw new Error(`${lane} report did not declare success.`);

    if (!Array.isArray(report.testResults) || !report.testResults.length)
      throw new Error(`${lane} report has no test files.`);
    const tests = new Map();

    for (const file of report.testResults) {
      if (!Schema.is(reportFile)(file))
        throw new Error(`${lane} report has an invalid absolute file path.`);
      const relative = paths.relative(root, file.name);

      if (
        !relative ||
        relative === ".." ||
        relative.startsWith(`..${paths.sep}`) ||
        paths.isAbsolute(relative)
      )
        throw new Error(`${lane} file path is outside the repository root: ${file.name}`);
      const filename = paths === path.win32 ? relative.replaceAll("\\", "/") : relative;

      if (file.status !== "passed")
        throw new Error(`${lane} file ${filename} failed or has an invalid status.`);

      if (!Array.isArray(file.assertionResults) || !file.assertionResults.length)
        throw new Error(`${lane} file ${filename} has no test results.`);

      for (const result of file.assertionResults) {
        if (!Schema.is(reportCase)(result))
          throw new Error(`${lane} file ${filename} has a malformed test name or status.`);
        const identity = JSON.stringify([filename, result.fullName]);
        const label = `${filename}: ${result.fullName}`;

        if (tests.has(identity)) throw new Error(`${lane} duplicate test identity ${label}`);

        if (result.status === "failed") throw new Error(`${lane} test ${label} failed.`);
        tests.set(identity, { label, status: result.status });
      }
    }

    return tests;
  }

  const left = collect(release, "release");
  const right = collect(prerelease, "prerelease");

  for (const [identity, test] of left) {
    if (!right.has(identity)) throw new Error(`${test.label} is missing in prerelease.`);
  }

  for (const [identity, test] of right) {
    if (!left.has(identity)) throw new Error(`${test.label} is missing in release.`);
  }

  let releasePassed = 0,
    prereleasePassed = 0;

  for (const [identity, test] of left) {
    const other = right.get(identity);

    if (test.status !== "passed" && other.status !== "passed")
      throw new Error(
        `${test.label} never passed: release=${test.status}, prerelease=${other.status}`,
      );

    if (test.status === "passed") releasePassed++;

    if (other.status === "passed") prereleasePassed++;
  }

  const releaseExcluded = left.size - releasePassed;
  const prereleaseExcluded = right.size - prereleasePassed;

  return {
    total: left.size,
    releasePassed,
    prereleasePassed,
    releaseExcluded,
    prereleaseExcluded,
    crossLaneExclusions: releaseExcluded + prereleaseExcluded,
  };
}

if (import.meta.main) {
  const args = process.argv.slice(2);

  if (args.length !== 3) {
    console.error(
      "Usage: bun scripts/browser-test-coverage.mjs <root> <release.json> <prerelease.json>",
    );
    process.exitCode = 2;
  } else {
    try {
      const [release, prerelease] = await Promise.all(
        args.slice(1).map(async (filename) => JSON.parse(await readFile(filename, "utf8"))),
      );

      console.log(JSON.stringify(compareBrowserReports(release, prerelease, { root: args[0] })));
    } catch (error) {
      console.error(`Browser test coverage: ${error.message}`);
      process.exitCode = 1;
    }
  }
}
